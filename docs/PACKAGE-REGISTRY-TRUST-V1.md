# Package registry trust v1

Status: additive TUF-style local policy and verifier; not TUF compliant,
not a hosted registry, and not an authority-bearing fetch implementation.
Audience: package-registry, security, and host-integration contributors.

## Scope and authority

`package_registry::trust` combines Ed25519 verification with exact
[Registry Snapshot v2](PACKAGE-REGISTRY-SNAPSHOT-V2.md) and
[Artifact Manifest v1](PACKAGE-ARTIFACT-MANIFEST-V1.md) replay. Its root,
publisher/targets, snapshot, and timestamp roles follow [TUF 1.0.26](https://theupdateframework.github.io/specification/v1.0.26/),
but SEMAPRAX wire is not TUF-compatible.

The embedding host supplies an independently installed root, trusted prior
checkpoint data, and one fixed Unix-seconds update-start time. There is no
production root, generated signing key, toolchain-release identity reuse,
implicit root download, clock read, network, filesystem, process, or publication
effect. Distribution bytes must never select their own root or checkpoint.
The initial checkpoint constructor is for explicit first installation only,
never recovery from a missing, corrupt, or rolled-back store.

`verify_update` returns only a `RegistryUpdateCandidate`: cryptographically
verified evidence plus the required next checkpoint and a SHA-256 binding to
the exact previous checkpoint bytes. It is not a durable commit, permission,
fetch capability, or evidence that a store prevented rollback. No conversion
to such a capability exists. Its artifact and lock checks are pure comparisons
under the candidate's fixed verification-time context; they do not refresh
expiry or authorize later use.

Before any authority-bearing consumer can use this result, a separate host
must authenticate and lock the real checkpoint store, recheck the selected
root/time/input bytes, durably compare-and-commit the complete transition
against `prior_checkpoint_digest`, and coordinate recovery with cache effects.
The additive local host below implements a separate managed generation store.
`fetch --lock` remains the earlier offline integrity boundary and gains no
registry-trust claim or access to that store.

## Wire and bounds

All trust documents are compact JSON, with lexicographically sorted object
keys, exact closed fields, canonical string/number spelling, no duplicate keys,
and no trailing newline. The existing bounded compact JSON scanner runs before
DOM parsing; parsing must reproduce the exact original bytes. Arrays retain
their input order; signature and checkpoint digests bind that order.
All integers are unsigned 64-bit; versions, expiry, and file lengths are
positive. Expiry uses Unix seconds. Text fields are at most 512 bytes; registry
and role names are 1–128 bytes from lowercase ASCII, digits, dot, and hyphen.

Each trust document is at most 1 MiB. A root has at most 64 distinct keys and
19 roles: root, timestamp, snapshot, and at most 16 publisher roles. Each
metadata signature list is at most 64 entries; a root rotation may carry up
to 128 signatures for the union of old and new key sets. The complete publisher target inventory
is bounded by the registry's 256 entries. The exact registry snapshot retains
its existing 16 MiB bound; each manifest retains its 256 KiB bound and closed
three-artifact linked scalar Wasm profile.

Hashes below are `sha256:<64 lowercase hex>` over the exact referenced bytes.
Raw public keys are 32-byte lowercase hex; signatures are 64-byte lowercase
hex. A key ID is the raw SHA-256 digest of its 32 public-key bytes, preventing
one public key from masquerading as several threshold participants.

### Independently installed root

Exact root fields are `schema`, `registry`, `version`, `expires`, `keys`,
and `roles`; schema is `semaprax.registry-trust-root.v1`.

Each key row contains `keyid` and `public`. Weak Ed25519 keys and duplicate
IDs reject. Each role row contains `name`, `namespace`, `keyids`, `threshold`.
All key IDs must exist, each may occur in exactly one role, and no key is left
unused. Each role requires a positive threshold no larger than its distinct
key inventory. Deployments should use independently held multiple root and
publisher keys; the wire supports one-key thresholds but does not recommend
them for production.

`root`, `timestamp`, and `snapshot` have empty namespace strings. Every other
role delegates one dotted package prefix ending in `.` (for example `acme.`).
Prefixes must be valid package identities before the terminal dot, cannot be
`std.` or descend from it, and cannot overlap another delegated prefix.
There is no wildcard, ordered fallback, recursive delegation, or ambient
default publisher. `acme.` authorizes `acme.math`, not `acmeevil.math` or `acme`.
The legacy publication `signature.identity` remains an opaque historical claim;
the authenticated publisher is the installed role's actual signing-key set.

### Signed metadata

Each envelope has exactly `signed` and `signatures`. Signature rows contain
`keyid` and `sig`. The exact signed object has `schema`, `registry`,
`root_digest`, `role`, `version`, `expires`, and `payload`; schema is
`semaprax.registry-trust-metadata.v1`. The root digest is the raw SHA-256 of
the installed root's canonical bytes. Signature input is the UTF-8 bytes
`semaprax.registry-trust-metadata.v1`, then NUL, then the signed object's exact
canonical JSON. `ed25519_dalek::VerifyingKey::verify_strict` performs the check.

Every listed signature must be valid and from a distinct key authorized for
that role; unknown, duplicate, wrong-role, weak, malformed or invalid signatures
refuse. Satisfying only part of the role's threshold refuses. Role separation
prevents a timestamp or snapshot key from signing publisher targets or roots.

A file reference is exactly `{length, sha256}`. A metadata reference is
exactly `{version, file}`, where `file` is a file reference to the complete
signed envelope, including signatures.

- Timestamp payload: `{snapshot}` containing the snapshot metadata reference.
- Snapshot payload: `{registry, publishers}`. `registry` references the exact
  Registry Snapshot-v2 envelope. Every publisher row is `{role, metadata}`,
  with one exact metadata reference for each installed publisher role.
- Publisher payload: `{targets}`. Each target row is
  `{package, version, manifest}`. `manifest` references the exact canonical
  Artifact Manifest-v1 bytes, not merely parsed fields or its claimed digest.

The supplied publisher roles must match the complete installed role inventory,
and each package/version must occur exactly once under its permitted namespace.
The union of publisher targets must exactly match the registry entry inventory.
No unsigned entry, duplicate coordinate, missing/extra publisher or manifest
splice is admitted. The verifier also calls registry-v2 `verify_snapshot` with
independently supplied `ManifestBoundEntry` values. Those can be created only
by existing verified Linked Build-v2 admission; decoded entries cannot be
promoted by this module. Cryptographic signatures do not replace independent
source/build/API replay.

### Root rotation

`verify_root_rotation` accepts a root envelope with `signed` equal to the
candidate root object and `signatures` in the same signature-row format. Its
signature domain is `semaprax.registry-trust-root.v1` plus NUL, followed by the
candidate root's canonical bytes. The registry identity cannot change and the
version must be exactly current version plus one, without overflow.

The signatures must meet both the currently trusted root-role threshold and
the candidate root-role threshold. Unknown and duplicate signers refuse;
a key shared between successive root-role sets may count once toward each
threshold. Expired old roots can authenticate recovery, but the new root must
be unexpired at the supplied time. The result is a `RootRotationCandidate`
with the old digest and new root, not a durable installation. Sequential
transitions must be retained and committed by the future trusted host. Metadata
must bind the new exact root digest and pass its new role keys, so old publisher
keys cannot authorize an update after rotation. Replaying a root older than
the trusted checkpoint fails closed.

## Checkpoint and freshness

Checkpoint schema is `semaprax.registry-trust-checkpoint.v1`; exact fields are
`schema`, `registry`, `root_version`, `root_digest`, `observed_time`, `roles`.
Each role stamp is `{role, version, digest}` with the exact metadata envelope
digest. Rendering sorts role stamps by role name. Older stamps for temporarily
removed publisher roles remain in the checkpoint, subject to the same 19-role
bound, so reintroducing a role cannot silently reset its high-water mark.

Root, timestamp, snapshot and publisher metadata must be unexpired at the one
fixed supplied time; equality with expiry is expired. Time must not precede
the previous checkpoint's observation. Every received role version must be at
least its checkpoint version; equal versions must have identical exact bytes.
Timestamp references must match snapshot version, length and hash, and
snapshot references must match every publisher and registry byte stream.
These checks reject rollback, same-version equivocation, mix-and-match, and
expired offline metadata under the supplied time/checkpoint assumptions.

An invalid update produces no checkpoint candidate and mutates nothing. This
is complete-set local verification, not TUF's incremental durable timestamp
and snapshot update workflow. No claim is made that an embedding caller which
discards or resets its checkpoint is protected from rollback or freeze.

Yank status is authenticated through the signed exact registry snapshot.
Candidate lock and artifact checks always refuse yanked entries; this initial
policy has no override. A lock must independently replay its exact subject
set, and each supplied subject must be byte-identical to an active entry.
Artifact checks bind coordinate, admitted manifest path, exact length and hash;
they do not execute artifacts or claim availability at a mirror.

## Diagnostics and evidence

| Code | Meaning |
| --- | --- |
| `SPX-PKR621` | Noncanonical/oversized wire, closed-policy shape, key, namespace or threshold refusal. |
| `SPX-PKR622` | Invalid/missing/duplicate/unauthorized signatures or wrong delegated namespace. |
| `SPX-PKR623` | Expiry, backwards time/version, same-version equivocation, or root mismatch. |
| `SPX-PKR624` | Exact metadata, inventory, manifest or artifact association disagreement. |
| `SPX-PKR625` | Absent or yanked selected subject/artifact. |
| `SPX-PKR626` | Local held-store authority, pin, shape, capacity or precommit exact-state refusal. |
| `SPX-PKR627` | Retained/ambiguous local effects requiring explicit exact revalidation recovery. |

Existing independent registry, manifest, and Lock-v3 replay diagnostics remain
unchanged. Focused tests live in `src/package_registry/trust/tests.rs`; their
keys are deterministic test-only material and never production trust anchors.
They use real Linked Build-v2 admission for the accepted registry entry and
exercise real Ed25519 signatures, threshold/wrong-key refusal, namespace and
manifest substitution, expiry, rollback/equivocation, mix-and-match, root
rotation, revoked publishers, artifact bytes, yanks, checkpoint round-trip,
and refusal without independently admitted entries.

Remaining work includes authority-bearing fetch integration, explicit transport/mirror
capabilities and availability tests, deployed publisher key custody and
rotation operations, and authorized hosted evidence. This local verifier
creates no authority for those actions and does not complete R19.

## Explicit local durable host

`trust::host::HeldTrustStore` is an additive Linux/Android/Apple local host,
not a production trust deployment or a new CLI. Unsupported hosts refuse
`open` without effects. No ambient clock, network, key, home or publication
authority is acquired. The embedding caller explicitly supplies the existing
store directory, independently obtained bootstrap root digest, immutable input
bytes, independently admitted entries and fixed trusted Unix-seconds time.
The module cannot authenticate the pin's origin or the clock's truth. Deriving
the pin from downloaded root bytes defeats its trust assumption.

The directory must already exist, be owned by the effective user, and have no
group/world permission bits. Every ancestor is opened without following links
and retained; subsequent operations recheck the held directory chain. Absolute
and ordinary relative paths work; parent traversal (`..`) is refused. A held
directory lock serializes cooperating writers. Files are owner-private,
single-link regular files opened with nofollow; inode/name association and
bounded exact bytes are checked. Hostile mutation by the same principal,
administrative whole-store rollback/deletion, compromised storage, and a
filesystem that lies about synchronization are excluded. This is not hardware
antirollback or protection against an attacker controlling the trusted host.

`install` is explicit bootstrap into an empty directory, requiring an independent
pin equal to the exact canonical root digest and an unexpired root. The initial
checkpoint records the supplied install time. `open` never repairs or bootstraps
missing/corrupt state. The initial root bytes and pin binding remain in the
immutable predecessor chain. Root rotation is accepted only together with a
fresh verified update, using the existing exact one-version dual-threshold
rotation and retaining its signed envelope; there is no unsigned root replacement
or implicit key reset. Successive rotations each require such an update.

`commit_update` takes fresh metadata and independently admitted entries, not a
`RegistryUpdateCandidate` supplied as authority. Under the lock it rechecks the
loaded exact root/checkpoint and ACTIVE bytes, replays signatures, freshness,
registry admission, optional Lock-v3 and exact subject selection, and all supplied
manifest-bound artifact associations. The candidate's prior-checkpoint digest must equal the
hash of the stored checkpoint string bytes. Artifacts additionally must belong
to selected lock subjects when a lock is supplied. Without a lock, artifacts are
admitted by their exact signed manifests, not by a dependency-closure claim.
An empty cache selection may advance trust alone; nonempty subject selections
require a complete valid lock. Each artifact is a
byte buffer, not a path to open. No executable artifact is run.

Trust state and selected cache bytes are one canonical
`semaprax.registry-trust-generation.v1` JSON file, at most 64 MiB. Fields are
`schema`, `previous`, `root`, `checkpoint`, `rotation`, `time`, `metadata`, and
`cache`. Root/checkpoint and metadata are exact original strings; artifacts are
lowercase hex byte strings. The generation name is `g-` plus its raw lowercase
SHA-256 hex. At most 64 immutable generations are retained; selected artifact
payloads total at most 16 MiB and at most 768 entries, with no duplicate
coordinate/path. Capacity refuses before staging; no automatic GC exists.

Effect ordering is:

1. Create-new `PENDING`, write the complete generation, sync its file, verify
   exact bytes and sync the held directory.
2. No-replace rename to the generation name and sync the directory.
3. Create-new and sync `ACTIVE.next` containing the exact generation name;
   create-new and sync `COMMIT` with the same name.
4. Recheck predecessor ACTIVE and generation bytes, rename `ACTIVE.next` to
   `ACTIVE`, and sync the directory. This is the single coordinated trust/cache
   visibility pivot, not a transaction across arbitrary paths or the old cache.
5. No-replace rename `COMMIT` to `c-<generation-name>`, sync the directory, then
   recheck the complete chain/inventory before returning a receipt.

Every predecessor requires its exact completed marker. Ordinary open rejects
pending files, orphan generations, missing markers, unknown inventory, digest
tamper, and an ACTIVE rollback leaving later generations. It also syncs the
directory before returning. Failures after effects return no success receipt;
files are never deleted or rolled back. The retained COMMIT marker makes an
interrupted ACTIVE switch an explicit recovery condition.

`recover_update` requires the independently retained predecessor generation
digest and exact original update request. It validates the predecessor chain,
replays the original fixed-time generation byte-for-byte, and separately
rechecks metadata at the supplied recovery time, which cannot precede the
original time. Only the exact complete pending generation, its no-replace
published form, or its already-pivoted ACTIVE can finish. Unknown effects,
changed request bytes, partial stage writes, or expired metadata fail closed
without deletion. `recover_install` similarly requires the original root, pin
and install time plus a fresh recovery time; ordinary open never invokes it.
Partially written stages require external operator reconciliation; this module
does not guess ownership of or truncate an interrupted file.

Current registry-v2 admission requires a linked Build-v2 root. The source
capsule requires two through four modules reachable from that root, whereas a
complete acyclic semantic lock includes a leaf. Until an independently verified
leaf-package admission profile exists, this store claims only manifest-bound
artifact cache commits, not a demonstrated complete registry-to-Lock-v3 fetch
workflow. Neither admission rule is weakened to manufacture such evidence.

The non-cloneable held store returns only `CommitReceipt` digest evidence, not
a reusable/serializable fetch token. This batch provides no managed-cache read
or execution route. The pure candidate remains non-authoritative and the
existing flat `fetch --lock` cache remains untouched. Tests in
`trust/host/tests.rs` cover local physical bootstrap, held lock/permissions/link
refusal, exact durable checkpoint and real manifest-artifact update, signed root
rotation/revocation, crash-point recovery, partial-write
fail-stop, tamper/retained-history rollback, stale time and yanked selection.
Those local tests do not establish physical power-loss or cross-host durability.
