# Registry-v3 durable local host v2

Status: additive explicit local host for signed Registry-v3; not a hosted
registry, authority-bearing fetch route, or physical power-loss certification.

## Authority and API

`package_registry::trust::host::registry_v3` owns a separate generation-v2
protocol over the existing held Unix store primitive. Linux/Android/Apple
support it; unsupported hosts refuse `open` without effects. Its owner-private
directory, retained nofollow ancestor chain, single-link regular files,
exclusive cooperative lock, bounds and filesystem assumptions follow
[Trust v1 host](PACKAGE-REGISTRY-TRUST-V1.md#explicit-local-durable-host).
There is no ambient time, network, key generation, publication or executable
artifact invocation. The caller must authenticate the independent bootstrap
root pin and trusted fixed time; the module cannot establish their provenance.
Hostile same-principal changes, whole-store rollback, compromised host/storage
and lying fsync are excluded, not solved by the digest chain.

`HeldTrustStore::install(path,root,pin,time)` requires an existing empty private
directory and fresh exact pinned root. `open(path,pin)` authenticates retained
bootstrap/rotation/protocol/checkpoint lineage and complete inventory, never
repairs or initializes missing state. Open does not refresh metadata or confer
permission to use cached artifacts. `receipt()` returns only generation and
checkpoint digests for retaining the exact retry predecessor.

`Update` borrows a sealed producer-backed Registry-v3 via signed metadata-v2
`UpdateInputs`, optional signed root rotation, a required complete Lock-v3 and
exact subjects, selected artifact byte buffers and one trusted update-start
time. A decoded inspection snapshot cannot be used. `commit_update` accepts
this request, not a candidate as authority. Under the held lock it rechecks
exact ACTIVE/root/checkpoint bytes and pin lineage, verifies signatures and
freshness using [Trust v2](PACKAGE-REGISTRY-TRUST-V2.md), replays complete
Lock-v3 source/report/compiled dependency selection, and checks all artifacts.

The cache selection must include exactly one manifest-bound `module.wasm` for
every locked coordinate. Additional admitted build-evidence/manifest rows are
optional, but only exact paths/bytes of those same selected coordinates are
accepted. Missing leaf modules, duplicate coordinate/path rows, unknown paths,
extra unlocked coordinates, malformed locks, yanks and tamper fail before any
staging. This is the closed scalar profile, not arbitrary cache completeness.
No reusable fetch/read/execute token is returned, even after durable commit.

## Generation-v2 and exact CAS

The canonical sorted compact JSON schema is
`semaprax.registry-trust-generation.v2`. Closed fields are `schema`,
`transition`, `previous`, `root`, `checkpoint`, `rotation`, `time`, `metadata`,
`cache`. `transition` is `bootstrap`, `update`, or `migrate-v1`. `previous` is
the exact predecessor `g-<sha256 hex>` name, empty only for bootstrap.
Root and Checkpoint-v2 are exact canonical JSON strings; `rotation` is the
exact signed root-rotation envelope or null. Time equals checkpoint observed
time. Bootstrap metadata/cache/rotation are null. Update metadata contains
exact `timestamp`, `snapshot`, `publishers` rows `{role,bytes}`, and the
Registry-v3 envelope `registry`. Cache contains exact `lock`, `subjects`, and
artifact rows `{package,version,path,hex}` with lowercase hex payload bytes.
Host-owned artifact rows are sorted by package/version/path, publisher envelope
rows by role, and subject strings by exact UTF-8 bytes. Permuting these input
slices produces identical generation bytes. Signed documents and lock bytes
themselves are never rewritten or repaired.

The generation remains bounded to 64 MiB, selected payloads to 16 MiB/768 rows,
and retained predecessor chains to 64 generations. Capacity fails before
effects; no GC or rollback deletion is introduced. The required prior
checkpoint digest is computed from the exact complete Checkpoint-v2 bytes,
not a reconstructed subset. The retained held generation and ACTIVE names
also undergo byte-exact CAS immediately before staging/pivot.

One immutable generation carries root, checkpoint, full lock selection and
all selected cache bytes. The existing effect ordering remains: exclusive
PENDING write/file+directory sync; no-replace immutable generation rename/sync;
ACTIVE.next and COMMIT write/sync; exact predecessor check and ACTIVE rename/
directory sync; no-replace completion marker and directory sync; final chain
recheck. Any ambiguous effect returns no success receipt and requires explicit
recovery. This gives one managed-generation pivot, not atomic visibility for
arbitrary raw-path readers or the existing flat `fetch --lock` cache.

## Explicit one-way migration

`migrate_v1(path,pin,expected_generation_digest,update)` is separate from open.
It locks and authenticates the complete old v1 chain, requires exact current
ACTIVE/generation digest and independent bootstrap pin, and seeds the sealed
Checkpoint-v2 namespace floor from the exact root recorded in that checkpoint.
Every prior role-version/digest and observed time is retained. Metadata-v2
changes signed bytes, so previously stamped roles require increased versions;
same-version migration is equivocation, not reset. Root rotation is permitted
only through its dual-threshold envelope and may not rename/reassign publisher
namespaces. A complete genuine v3 lock/cache request is mandatory for migration.

The migration compares the complete old generation bytes again before effects;
the migrated wrapper's prior digest does not substitute for the old stored
v1 checkpoint CAS. Exactly one v1-to-v2 boundary may occur. A v2 predecessor
cannot be followed by v1, and a v2 head cannot reopen via the unchanged v1
decoder. Normal v3 open refuses a v1 head, demanding explicit migration.
Existing v1 wire, ordinary host routes and flat fetch semantics are unchanged.

## Exact recovery and limits

`recover_update` and separate `recover_migration_v1` require the independently
retained predecessor digest and the original full immutable request, including
sealed admission, lock, subjects and every artifact byte. The held predecessor
chain and protocol route are revalidated, metadata is checked at explicit
recovery time (not earlier than original time), and original fixed-time prepare
must reproduce the pending generation exactly. `recover_install` similarly
requires original root/pin/time plus fresh recovery time. Unknown inventory,
partial stages, changed request bytes, stale time or incomplete artifacts refuse
without deleting or repairing anything. Normal open refuses pending/orphan/
ambiguous state and ACTIVE rollback leaving later generations. Decoded history
is trusted-store lineage, never a route to reconstruct producer admission.

The low-level recovery helper accepts an internal predecessor decoder callback;
the v1 wrapper still passes its original closed v1 decoder. Both versions use
the same unchanged filesystem effect ordering. The v2 callback follows a
v1/v2 chain only after the owning loader authenticated its lineage.

Focused selector `package_registry::trust::host::registry_v3::tests` owns nine
regressions covering genuine root/leaf success, mandatory core inventory,
pin/private-path/lock/downgrade refusal, full-lock/cache/time/yank/rollback,
signed rotation, simulated bootstrap/update crash points, exact retry, tamper/
orphans/ACTIVE rollback, and real stamped-v1 migration/version/CAS/recovery.
The existing nine v1 host tests guard the shared recovery extraction. Simulated
crash hooks test logical fail-stop behavior; they are not physical power-loss,
hosted deployment or storage-hardware evidence. Matrix status remains partial.
