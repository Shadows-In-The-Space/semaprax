# Package registry mirror flow v1

Audience: package-registry host implementers and trust-boundary reviewers.

Status: additive local composition of existing bounded mirror acquisition,
Registry-v3 signed proof, held-generation commit, and one live artifact read.
It is not a hosted registry, root discovery, resolver-cache publication,
installation, execution, or availability route.

`trust::host::registry_v3::acquire_commit_and_read` borrows one already
constructed `MirrorNetworkAuthority`, caller-provided transport and live
`HeldTrustStore`. Its request contains an independently installed root,
bridge-local `MirrorCheckpoint`, fixed update/read times, sealed Registry-v3,
complete Lock-v3 subjects, exact metadata paths, and caller-named digest-bound
metadata/artifact objects. A remote artifact path is never a local path: every
object also names a separate package/version/logical manifest path.

Before dispatch, the flow requires `MirrorCheckpoint::initial_at(root,time)`
and hashes its complete ordinary checkpoint wire to require equality with the
live held generation's checkpoint digest. Thus both root and caller-supplied
bootstrap trusted time must match the held bootstrap generation; a wrong time
or an initial checkpoint against a later generation fails before network. It
cannot reset the seven-day mirror age. This v1 composition deliberately
provides no mirror refresh or resume capability: a returned noninitial bridge
checkpoint is evidence only for a future protocol, not input to this flow.

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
execution permission. A bridge checkpoint remains caller-retained local state;
the ordinary checkpoint view alone cannot restart mirror freshness accounting.
If the held commit succeeds but the required final live read fails, the closed
post-commit result carries that commit receipt and next bridge checkpoint with
the diagnostic. It is deliberately distinct from a pre-effect refusal.

The local scripted test proves signed root/leaf metadata and two exact Wasm
objects travel through acquisition, proof, held generation and lock-bound live
read. Its negative controls prove a valid-digest but signature-tampered
timestamp response cannot mutate the held generation, and a request selecting
no matching artifact refuses before a transport call or held-generation
mutation. They also prove an initial bridge checkpoint cannot reset a
post-bootstrap store after seven days, and force a final held-read recheck
failure to expose a post-commit outcome rather than a no-effect refusal. This
establishes no TLS peer, DNS, Internet, hosted mirror,
production root/key, resolver cache, or physical-device support.
