# Package registry mirror flow v1

Audience: package-registry host implementers and trust-boundary reviewers.

Status: additive local composition of existing bounded mirror acquisition,
Registry-v3 signed proof, held-generation commit, and one live artifact read.
It is not a hosted registry, root discovery, installation, execution, or
availability route. The separately explicit local cache composition below is
the only resolver-cache route it supports.

`trust::host::registry_v3::acquire_commit_and_read` borrows one already
constructed `MirrorNetworkAuthority`, caller-provided transport and live
`HeldTrustStore`. Its request contains fixed update/read times, sealed
Registry-v3, complete Lock-v3 subjects, exact metadata paths, and caller-named
digest-bound metadata/artifact objects. A remote artifact path is never a
local path: every object also names a separate package/version/logical manifest
path.

Before dispatch, the flow obtains its root and complete `MirrorCheckpoint`
only from the live held generation. A v2 generation with no mirror anchor is
eligible only when it is the exact original held bootstrap; an ordinary or
prior one-shot update without an anchor refuses rather than minting a new
freshness window. A successful mirror pivot emits an immutable generation-v3
whose closed `mirror` field records the authenticated timestamp
version/digest and its first observation time. Later refreshes reconstruct
that anchor under the held lock; callers cannot supply, reset, rewind, or
rebase it. Replaying identical timestamp bytes retains the stored observation;
only a newer signed timestamp moves it. Historical v2 generations remain
readable; this flow performs no automatic generation rewrite or migration.

The flow first obtains one bounded all-or-nothing batch through the existing
no-proxy/no-credentials/no-redirect transport. It authenticates only the
metadata subset through `verify_mirror_update`, then replays the exact lock and
each downloaded artifact against the sealed registry before requesting any held
store effect. It also preflights the requested nondecreasing read time against
the next ordinary checkpoint, so an expired read cannot first create a durable
generation. The existing Host-v2 commit independently repeats metadata, lock
and manifest verification under its live generation lock. Finally, the flow
uses the new committed generation digest and exact Lock-v3 bytes for one live
`read_artifact` call; the returned `VerifiedArtifact` therefore retains the
ordinary held ACTIVE, fixed-time, selected-subject and manifest checks.

The result contains only commit/read evidence and the next bridge checkpoint.
It supplies no durable network capability, raw filesystem path, root/publisher
authority, cache writer, serialization token, installation permission or module
execution permission. The returned checkpoint is evidence, not a resume input:
the next flow derives its state from the held generation instead.
If the held commit succeeds but the required final live read fails, the closed
post-commit result carries that commit receipt and next bridge checkpoint with
the diagnostic. It is deliberately distinct from a pre-effect refusal.
The mirror-specific commit path also returns that closed post-commit form with
`SPX-PKR628` if its final held recheck fails after the immutable pivot; the
receipt is evidence for explicit revalidation, never permission to retry or
read.

If the lower held publish boundary itself reports `SPX-PKR627`, the flow
returns a distinct `Uncertain` outcome with only the candidate generation
digest and next bridge evidence—never a receipt or a no-effect claim. PENDING,
an immutable generation, or ACTIVE may exist, so normal exact recovery and
revalidation remain required.

The local scripted test proves signed root/leaf metadata and two exact Wasm
objects travel through acquisition, proof, held generation and lock-bound live
read, followed by a replay refresh and reopen. Its negative controls prove a
valid-digest but signature-tampered timestamp response cannot mutate the held
generation, a replay after more than seven days remains refused after reopen
under long-lived root and metadata fixtures,
an anchorless non-bootstrap generation cannot start a new mirror bridge, and a
request selecting no matching artifact refuses before a transport call or held
generation mutation. They also force a final held-read recheck failure to
expose a post-commit outcome rather than a no-effect refusal, force the
post-pivot held recheck into receipt-bearing `SPX-PKR628`, and reject an
internally attempted candidate made from `initial_at` because its predecessor
does not bind the live held checkpoint. An injected lower held-publish
`AfterActive` failure reports the non-receipt `SPX-PKR627` uncertainty form.
This establishes
no TLS peer, DNS, Internet, hosted mirror,
production root/key, resolver-cache trust authority, or physical-device support.

## Explicit cache and resolution composition

`trust::host::registry_v3::acquire_commit_cache_and_resolve` is an additive
local composition over the completed mirror flow. Its caller supplies the
ordinary cache destination path, a fixed cache time no earlier than the final
held artifact-read time, and a Resolver-v2 template (requirements, target,
allowed capabilities and output bound). It derives the generation digest,
sealed Registry-v3, Lock-v3 and selected Subject-v3 inventory only from the
successful held commit; it accepts neither a root, checkpoint, caller-selected
generation digest, cache-discovery route nor a reusable cache capability.

After the receipt-bearing held commit/read succeeds, the existing cache bridge
revalidates every selected artifact at the fixed cache time and publishes the
exact subject inventory. The composition reopens only receipt-named
`<sha256 hex>.json` files through the cache writer's held directory-FD,
nofollow, bounded regular-file reader while it holds the cooperative cache
lock. It independently checks every name/digest/coordinate against the receipt,
then generates and verifies Resolver-v2 evidence and requires its Lock-v3 to
equal the sealed lock before independently checking the signed root/leaf lock
selection. Other cache entries are neither discovered nor resolver input.

`MirrorCacheFlowError::Mirror` preserves the underlying pre-effect proof,
publish-uncertain and receipt-bearing post-commit outcomes unchanged. A cache
failure occurs after a confirmed held commit and is conservatively reported as
`CachePartial` with commit/checkpoint evidence but no cache receipt: an
authenticated prefix or stage may remain. A later cache replay or resolver
failure reports `Resolution` with the completed cache receipt, never as an
earlier no-effect refusal. There remains no cross-store atomic transaction,
ambient network/cache discovery, cache-carried signature/freshness authority,
installation, execution, hosted registry, TLS-peer, DNS, Internet, production
root/key or availability claim.
