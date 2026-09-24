# Package registry mirror trust v1

Status: additive local byte-to-proof composition. It is not hosted registry,
root discovery, durable storage, cache publication, execution or availability
support.

`trust::registry_v3::verify_mirror_update` accepts only `MirrorBytes` produced
by the separate explicit HTTPS authority, an independently installed root,
trusted RegistryCheckpoint-v2, fixed caller time, independently producer-sealed
Registry-v3, and one exact timestamp/snapshot/publisher metadata path set.
All returned rows must be metadata, have exactly the named paths, and have no
duplicates or extras. Bytes must be UTF-8 canonical trust documents. The bridge
then invokes the ordinary Trust v2 verifier; it does not parse a decoded
registry, select a root, or substitute mirror digests for signatures.

Thus timestamp pins snapshot; snapshot pins the exact sealed Registry-v3
envelope and every publisher envelope; publisher roles authenticate exact
manifest schema/digest/file bytes for the complete inventory. Existing
threshold, namespace, manifest, yanked lock/artifact, rotation/revocation and
checkpoint anti-rollback checks remain the only admission decision.

Wavect's local mirror policy additionally refuses an update more than seven
days after the last successfully checkpointed timestamp observation. Explicit
first installation is exempt because it lacks a prior timestamp observation.
This conservative offline-staleness cap is not a clock source and does not
weaken ordinary metadata expiry; expiry equality, backwards time, bad rotation
or stale high-water marks still fail closed.

Replaying identical signed timestamp version-and-digest bytes may be verified
inside that interval, but it retains the preceding bridge observation rather
than advancing it. Only a newer authenticated timestamp advances the local
offline-age anchor, so repeated mirror replay cannot refresh the seven-day
window without new signed freshness evidence.

The focused `trust::registry_v3::tests` case acquires signed fixture bytes via
an in-process transport and proves complete replay, signature tamper refusal,
and the seven-day offline refusal. This is local verification only, not a TLS,
DNS, hosted-mirror, production-key or physical-device claim.

No Wavect GmbH production registry root, operational registry owner, or package
publisher key custody is provisioned here. In particular, a GitHub release or
workflow identity is not package-publisher authorization and cannot substitute
for independently installed root material.
