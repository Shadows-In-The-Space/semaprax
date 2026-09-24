# Registry-bound resolution v1

Status: implemented, **local-only** bounded module. Unit-tested in this
worktree (`cargo test --locked -p semaprax --lib package_registry::binding::`);
not run through `scripts/quality.sh full`, not released, not hosted, and not
wired into any authority-bearing CLI route. `semaprax registry lock` and
`registry verify` compose this format read-only; `registry lock ... --raw`
emits its exact canonical bytes. There is no hosted or production Semaprax
registry, and this format does not create one.

Audience: package-tool authors and compiler contributors working on issue #195.

`crate::package_registry::binding` sits above [Registry Snapshot v1](PACKAGE-REGISTRY-SNAPSHOT-V1.md)
and [Resolver v2](OFFLINE-PACKAGE-RESOLVER-V2.md). Resolver evidence commits
only to the supplied `subjects: Vec<String>` catalog, not to which snapshot or
yank policy* produced those subjects. Two different snapshots can project the
identical subject list for the packages one resolution actually selects — for
example, a snapshot with an extra `Yanked` entry that `YankPolicy::ExcludeYanked`
drops during projection, versus a snapshot that never published that entry at
all — and resolve to byte-identical resolver-v2 evidence even though the
registries, and therefore their full published history, genuinely differ. Held
on its own, resolver-v2 evidence cannot tell those two cases apart, so it does
not, by itself, "bind exact package digests, registry snapshot/metadata" the
way issue #195's implementation sequence requires of a lockfile.

## What this is not

This is composition, not new solving or signing logic. `bind_to_snapshot`
calls the existing `project_subjects` and `package_resolver_v2::generate`
exactly as the snapshot and federation test suites already do by hand;
`verify_bound_resolution` rebuilds the registry snapshot from caller-owned
entries and the resolution from a caller-owned template, byte-comparing both
against supplied evidence — the same replay discipline `verify_snapshot` and
`package_resolver_v2::verify` already use. Every nonclaim in the snapshot
specification holds here verbatim: `signature` stays opaque and is never
verified anywhere in this crate (issue #168, still open, owns the signing
key), `provenance_digest` stays an unverified reference, and nothing in this
module touches the network, the clock, the environment, or the filesystem.

## The model

`bind_to_snapshot(snapshot, policy, template, options)` renders one canonical,
content-addressed `semaprax.registry-bound-resolution.v1` envelope embedding:

1. the registry snapshot's own digest;
2. the `YankPolicy` applied when projecting it; and
3. the complete resolver-v2 evidence produced by resolving `template` (a
   `ResolutionTemplate` — the requirements, target and allowed capabilities
   `package_resolver_v2::ResolutionInput` needs beyond the `subjects` catalog
   a projection always supplies) against that projection.

`verify_bound_resolution(evidence, entries, policy, template, options)`
independently rebuilds the snapshot from `entries`, re-assembles the same
envelope, and requires a byte-exact replay before independently re-running
`package_resolver_v2::verify` on the embedded resolver evidence. On success it
returns the *independently rebuilt* snapshot digest, the selected package
coordinates, and any yank warnings — never values merely copied out of
`evidence`.

## Canonical envelope

```json
{"schema":"semaprax.registry-bound-resolution.v1","digest":"sha256:…","bytes":N,
 "payload":{"schema":"semaprax.registry-bound-resolution.v1",
  "snapshot_digest":"sha256:…","yank_policy":"exclude_yanked",
  "resolution":{"schema":"semaprax.offline-package-resolution-evidence.v2", "…":"…"}}}
```

`resolution` embeds the complete resolver-v2 evidence envelope verbatim, so a
byte-exact replay of the outer envelope implies a byte-exact replay of the
inner one. The outer envelope digest is domain-separated with
`semaprax.registry-bound-resolution.v1\0` and the payload length, so it can
never collide with a snapshot, federation, or resolver-v2 payload.

## Diagnostics

No new diagnostic code is minted. This module reuses two existing codes:

| Code | Meaning here |
| --- | --- |
| `SPX-PKR607` | Cumulative render-budget overflow, or evidence over the output-byte bound — same meaning as in the snapshot layer. |
| `SPX-PKR608` | `verify_bound_resolution` evidence does not byte-replay the supplied entries, policy and template — covers a tampered byte, a substituted registry entry, a retargeted requirement, and a substituted snapshot that would have resolved to the same package versions. |

A mismatched yank policy at verification time surfaces through whichever
existing snapshot-layer diagnostic `project_subjects` itself raises for that
policy (`SPX-PKR609` warning, `SPX-PKR610` refusal) — the binding layer adds no
policy logic of its own.

## Determinism

`bind_to_snapshot` and `verify_bound_resolution` read no clock, environment
variable, or filesystem, and use no `HashMap`/`HashSet` anywhere on this
module's own source
(`tests::determinism_argument_is_structural_not_just_repeated_runs` greps for
exactly those constructs). Calling `bind_to_snapshot` twice with the same
snapshot, policy, template and options always yields byte-identical evidence
(`tests::same_inputs_produce_byte_identical_bound_evidence_every_time`), and
verification is insensitive to the caller's entry-list order
(`tests::entry_order_does_not_affect_independent_reverification`), since
`build_snapshot` itself keys entries through a canonical `BTreeMap`.

## The property this module exists for

`tests::a_registry_change_invisible_to_the_resolver_still_changes_the_bound_digest`
builds two snapshots that project to the *identical* resolver-v2 subject list
for one resolution — one publishes only the needed package, the other
additionally publishes an excluded, yanked, unrelated package — and shows
their plain resolver-v2 evidence is identical while their bound evidence is
not, and that a bound envelope claimed for one registry does not independently
reverify against the other's entries.

## Evidence and nonclaims

`src/package_registry/binding/tests.rs` covers: repeat-call determinism,
entry-list-order independence, independent replay reporting the rebuilt
snapshot digest, the registry-change property above, a single tampered byte,
a substituted snapshot, a mismatched yank policy at verification time,
yank-warning pass-through, and the structural no-ambient-authority argument.
Every refusal test asserts the exact diagnostic code. Fault injection (each
behaviour disabled one at a time, confirmed to turn exactly its own test red,
then restored) showed: dropping the embedded snapshot digest turns red the
registry-change property test and the substituted-snapshot refusal test;
skipping the byte-for-byte replay comparison turns red the tampered-byte,
substituted-snapshot, and registry-change tests; and dropping warning
pass-through turns red only the warning-propagation test.

This is **local evidence** from unit tests in one worktree. The read-only CLI
route adds no network path, publication, or signature verification, and no
hosted or published registry is claimed or implied.
