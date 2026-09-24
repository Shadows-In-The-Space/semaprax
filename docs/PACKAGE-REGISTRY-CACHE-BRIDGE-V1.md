# Signed managed-store to resolver-cache bridge v1

Status: explicit offline host workflow. No online registry, mirror, transport,
install-script, hosted availability or execution support is claimed.

## Purpose and boundaries

The existing `resolve --cache` catalog consists of canonical Subject-v3 files
named `<subject digest hex>.json`. It does not store core Wasm artifacts or
publisher trust state. The additive
`trust::host::registry_v3::HeldTrustStore::populate_resolver_cache(path, request)`
connects a genuine signed root/leaf generation to this existing catalog format.
It does not invent an artifact-cache layout or upgrade the flat catalog into a
signed capability. Artifacts remain in the managed store and are consumed only
through its explicit [held read API](PACKAGE-REGISTRY-HOST-V2.md).

`CacheFill` supplies exact expected generation digest, exact Lock-v3 bytes,
producer-sealed Registry-v3 and trusted fixed time. The caller also explicitly
selects the destination cache path. No ambient network/path discovery or key
authority is introduced. Both ordinary relative and absolute cache paths retain
the existing lock-bound cache policy. Unsupported platforms have no held host
and cannot obtain this route.

The library-owned `package_cache_host` contains the original held nofollow
cache transaction formerly owned by `src/cli/fetch/locked.rs`. The CLI is now a
thin adapter to `fetch_locked`; grammar, supported platform cfg, diagnostics,
receipt bytes/order and failure semantics remain unchanged. Its original eight
hostile tests move with the implementation. No subject/lock verifier is weakened.

## Effect ordering and authority

The live source store lock is already held. The cache writer then holds the
destination directory chain and cooperative destination lock (nearest held
parent authority if creation is necessary). Locks are nonblocking; overlapping
or busy authorities refuse instead of waiting or bypassing a lock.

Before creating missing directories or staging subjects, the bridge rechecks
the exact source ACTIVE/chain and performs a live `read_artifact` for every
selected `module.wasm`. Those reads replay signed metadata at the supplied
trusted time, require the exact sealed registry and lock, verify complete
compiled root/leaf subject closure, and compare manifest-bound artifact bytes.
No artifact result is persisted outside the source store. The copied subject
inventory is exactly the immutable committed selection, independently replayed
by the existing Lock-v3 and Subject-v3 verifiers before any cache write.

Each source check retains the live held source authority through destination
publication. The callback rechecks ACTIVE/chain before/after stage writes,
before/after each no-replace publication, and after final settlement. Destination
entries are compared through held nofollow handles; a same-address collision is
not overwritten. Retained `.fetch-stage-*` files fail-stop subsequent attempts.
`CacheFillReceipt` reports source generation and lock digests and each copied
subject's coordinate/digest plus exact `present` state. It is plain evidence,
not a serializable trust bearer or permission to read, execute or fetch later.

## Failure and freshness limits

There is no cross-store atomic transaction. A later failure can leave staged
data or an authenticated published prefix in the ordinary cache. The writer
never deletes or rolls back names; after publication has begun it returns an
uncertain/partial diagnostic and no receipt. The source generation is never
modified by this operation. Caller reconciliation remains explicit. There is
no persistent manifest or trust sidecar that a consumer could accidentally
treat as authorizing cached subjects.

The source's trusted-clock/pin provenance, installed-state revocation limits,
cooperative lock and same-principal hostile mutation exclusions remain those
of [Host v2](PACKAGE-REGISTRY-HOST-V2.md). Fixed-time verification is invocation
bound, not perpetual freshness. The copied flat cache deliberately does not
retain signature, freshness or revocation authority: `resolve` still independently
verifies every subject, while subsequent artifact reads must again use the
held signed generation and trusted time. Discovering or acquiring remote updates
is a separate future authority boundary. Existing unlocked fetch is unchanged.

## Focused evidence contract

`package_registry::trust::host::registry_v3::tests::cache_tests` owns six cases:
real signed root/leaf generation → actual cache files → Resolver-v2 evidence
replay → identical Lock-v3; exact existing CLI receipt bytes/operand order;
wrong source/lock/registry/time before cache creation; collision/link/retained
stage refusal; source drift before staging; source drift after first publish
with retained prefix and no receipt. The eight relocated `package_cache_host`
tests retain partial-write, pathname-swap, competitor, receipt and no-delete
coverage. The existing project-harness lock-bound fetch case exercises the CLI
adapter. No completion-matrix gate or product status is advanced by this slice.
