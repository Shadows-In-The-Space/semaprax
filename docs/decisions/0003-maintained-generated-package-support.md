# ADR 0003: Maintained generated-package support for owned-data-api.v1 (Rust)

Audience: maintainers deciding GitHub issue #145's scoped publication
decision; compiler and release-tooling contributors.

- Status: **Accepted for scope only, on 2026-09-19, by the repository
  maintainer (Kevin, `kevin.riedl@wavect.io`, `wavect/semaprax` owner).** The
  maintainer approved this ADR's scope decision in session and delegated the
  eight open questions below to the implementing agent's judgment under one
  stated constraint: decide whatever is best for the language long term. The
  answers recorded in "Maintainer decision" below are that delegation
  exercised, written down by the agent as scribe rather than self-approved.
- **What is accepted is the scope, not a live support claim.** Questions 5 and
  7 are answered "evidence first", and that evidence does not exist today, so
  no package is described as maintained or supported yet. Accepting a scope
  decision does not manufacture the evidence the claim would need. See
  "Maintainer decision".
- Date: 2026-09-19

## Context

Issue #145 asks the repository to turn "one deliberately chosen existing
generated-package preview" into a maintained, reproducible consumer route,
without publishing anything, signing anything, or promoting the separate
public generic-ABI decision (owned by #144/SPX-AI-045). Its three
Definition-of-Done boxes are: (1) a scoped maintainer decision and maintained
package consumer gate exist; (2) only approved package artifacts are actually
published; (3) version/target/support claims match clean-install executable
evidence.

Prior commits `2ae8a968`, `88d826b0`, and `e0c7f192` did substantial work
toward this: `2ae8a968` added `scripts/generated-package-release.py`, a
release-preparation and dry-run-check wrapper around the compiler's existing
generated-package output; `88d826b0` and `e0c7f192` extended it with a
no-local-path/no-private-crate check against the packaging-normalized
`Cargo.toml` and a checksum/source-association gate. That work already
satisfies box 2 structurally: the tool refuses `--publish` unconditionally,
has no live-publish code path, and refuses outright if a
publish-credential-shaped environment variable is present (see
`scripts/generated-package-release.py:32-41` and `:118-126`). Re-verified
locally this session (macOS arm64, Darwin 25.5.0, this checkout):

```sh
python3 scripts/test-generated-package-release.py
# Ran 21 tests in 0.61s -- OK (no skips; both real-npm and real-cargo
# dry-run cases executed for real: npm 24.3.0 via nvm, cargo via Homebrew
# were both present on PATH)
```

`docs/GENERATED-PACKAGE-PUBLICATION-DECISION-DRAFT-V1.md` already exists as an
unapproved design draft naming the open human decisions (registry identity,
credentials, signing, CI wiring, tarball-install evidence). This ADR is the
same proposal reworked into the repository's ADR sequence and house format
(matching [ADR 0001](0001-graphify.md) and
[ADR 0002](0002-managed-workspace-generations.md)), with its support matrix
and evidence table re-verified against the current checkout rather than
carried forward unchecked -- and, in two places, corrected: the draft's
"Consumer install-from-tarball evidence" open item undersells how little
automated evidence currently exists, and this session found the profile's own
CI harness has no recent confirmed green hosted run (see Evidence below). The
draft is left in place as background design material; nothing here deletes or
supersedes its content, and a maintainer accepting a version of this ADR
should still resolve the draft's five open items.

Boxes 1 and 3 are the genuinely open ones, and box 1 requires an act of human
authority this document cannot perform. This ADR's only job is to make that
decision cheap and accurate to make.

## Decision

Recommend exactly one profile, and only its Rust package, as the first
maintained generated-package route:

| Field | Value |
| --- | --- |
| Project schema / profile | `semaprax.project.v8` / `owned-data-api.v1` |
| Generated Rust package identifier | `semaprax.native-rust-owned-data-sdk.v1` |
| Generated crate name / fixed version | `semaprax-generated-native-rust-owned-data-sdk` / `0.1.0` (constant; see Support matrix) |
| Owning specification | [docs/PUBLIC-OWNED-DATA-API-V1.md](../PUBLIC-OWNED-DATA-API-V1.md) |
| npm package for the same profile | **Not recommended this round** (see below) |

**Why owned-data-api.v1, specifically.** It is the one existing
generated-package route `scripts/generated-package-release.py` already wraps
end to end (`RUST_OWNED_DATA_FIXED_FILES` / `RUST_OWNED_DATA_ARCHIVE_NAMES` in
`scripts/generated-package-release.py:69-80`), the one the existing
unapproved draft names, and the one `docs/PUBLIC-OWNED-DATA-API-V1.md`
describes as feature-complete pending only the publication decision. It is
distinct from, and does not reinterpret, the separate general
native-rust-interop-v1 scalar SDK (calculator/callback profile,
`semaprax_native_rust_sdk`, its own `native-rust-sdk-v1` CI job) or the
generic-ABI packages this issue excludes.

**Why Rust only, not npm too.** Real npm-tarball consumption evidence does
not exist anywhere in this repository today, for any generated package,
hosted or local. The only tests that install and run from a real npm tarball
(`tests/frame_payload_product_v1/npm_installation.rs:60`,
`tests/image_packaged_typescript_workflow_v1.rs:715`) are both
`#[ignore]`d pending "provisioned NODE, NPM_CLI and TypeScript 5.8.3
TSC_CLI", and no CI job passes `--ignored` to unblock them. Recommending npm
now would make a box-3 support claim ("clean-install executable evidence")
that nothing backs. The Rust side is not perfect either (see Evidence), but
it has a defined package-generation wrapper, a dedicated test harness, and a
CI job wired to run it -- a narrower, fully evidenced proposal beats a wider
one resting partly on absent evidence.

**Why not the general native-rust-interop-v1 SDK instead.** That profile
already has better-exercised hosted CI (the dedicated `native-rust-sdk-v1`
job) and a real packaged-tarball consumer test
(`packaged_tarball_consumer_round_trips_with_preserved_lockfile_and_source_tied_checksum`,
added in `e0c7f192`), but issue #145 asks for one deliberately chosen
profile, and `scripts/generated-package-release.py` was built around
owned-data-api.v1's file inventory, not the scalar SDK's. Recommending both
under one decision would blur which support claims are backed by which
evidence; a maintainer wanting to promote the scalar SDK too should do so as
a separate, explicitly evidenced decision.

## Support matrix

| Claim | Exact value | Notes |
| --- | --- | --- |
| Targets (5, fixed) | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` | Per `docs/NATIVE-RUST-INTEROP-V1.md`'s "narrower five targets" rule, shared by the owned-data SDK's compiled-ABI admission (`docs/PUBLIC-OWNED-DATA-API-V1.md`). `aarch64-pc-windows-msvc` is explicitly excluded: its archive tool plan is not frozen. Musl, GNU-Windows, x32, and big-endian configurations are rejected before staging, not silently accepted. |
| Generated crate declared MSRV | `rust-version = "1.85"` | Literal in every generated `Cargo.toml` (`crates/semaprax-native-rust-owned-data-package/src/render.rs:26`). No exact-1.85.0 end-to-end build of *this* crate has been found; the nearest cited toolchain evidence (1.85.1) is for the separate scalar SDK and is explicitly marked "not exact 1.85.0, repository MSRV, Windows or hosted evidence" in `docs/PUBLIC-OWNED-DATA-API-V1.md`. |
| Toolchains that actually build/test this repository's own harness for this profile | Rust 1.97.1 (`verify-tests` CI job) | The profile's own test file, `tests/public_native_rust_owned_data_sdk_v1.rs`, is unconditionally selected into the `verify-tests` shard plan (`integration-3`, confirmed via `python3 scripts/ci-msrv.py --plan-only` this session), which pins Rust 1.97.1 and Node 22 -- not 1.85 and not the 1.88 pinned by the unrelated `native-rust-sdk-v1` job. |
| Package version scheme | Fixed literal `0.1.0` for every generated instance (`crates/semaprax-native-rust-owned-data-package/src/lib.rs:44-45`) | Compatibility is tracked by the exact public-API descriptor SHA-256 digest, not by incrementing this version (see the generated README template, `scripts/generated-package-release.py:262-270`). A registry requires monotonically increasing versions per crate name; publishing more than once under this scheme needs a version-assignment policy that does not exist yet (Open question 2). |
| Host OS claims | Local only: Linux AArch64/Rust 1.88/Clang 14, macOS AArch64/Rust 1.98 (`docs/PUBLIC-OWNED-DATA-API-V1.md`, "Scoped local execution... on Linux AArch64/Rust 1.88/Clang 14 passes nine selected tests... does not establish... hosted promotion") | The owning spec's own words already mark this local, not hosted, despite the harness now also being CI-selected (see Evidence). |
| npm package | Not proposed this round | See Decision. |

## Evidence

Every claim above and every element of Box 2/3 is backed by one of the rows
below. Each row states what was actually run or found, on what host, at what
commit, and what kind of evidence that makes it -- per this repository's
governing rule (AGENTS.md): local, proof-only, or prior-head evidence is
never described as hosted, current-head, or production support.

| # | Claim | Evidence | Kind |
| - | --- | --- | --- |
| 1 | Publish is refused unconditionally; no live-publish code path exists; credential-shaped env vars block both subcommands before any file is touched | `python3 scripts/test-generated-package-release.py` -> 21/21 passed, run this session on this macOS arm64 host at this checkout | **Local, current session, this host.** Not hosted CI; not a registry test. |
| 2 | `npm pack --dry-run` and `cargo publish --dry-run` independently confirm packaging validity/refusal using real tools | Same 21-test run: both `test_real_npm_pack_dry_run_succeeds_and_writes_nothing` and `test_real_cargo_publish_dry_run_is_refused_by_cargo_itself` executed (not skipped) against this machine's real `npm` (nvm, Node 24.3.0) and `cargo` (Homebrew) | **Local, current session, real tools, dry-run only.** No network call, no registry write; not evidence of a registry accepting the package. |
| 3 | Generated packages are deterministic (identical SHA-256 across two independent generate-and-package runs) and different source produces different digests | Described in issue comment for `e0c7f192`: "two generate-and-package runs from identical `.spx` source produce an identical SHA-256, and the calculator and callback programs produce different ones," with a stated negative control (flipped assertion fails) | **Local evidence at a prior commit (`e0c7f192`), not independently re-run this session.** Not hosted; not re-verified at the current checkout. |
| 4 | The owned-data-api.v1 Rust SDK's own test harness (`tests/public_native_rust_owned_data_sdk_v1.rs`) exists, is unconditionally selected (no env-var gate), and is wired into a hosted CI matrix | Confirmed this session via `python3 scripts/ci-msrv.py --plan-only`: the target lands in `verify-tests`'s `integration-3` shard, run across `ubuntu-latest`/`macos-latest`/`windows-latest` | **Structural fact about CI configuration, verified this session by reading, not by a passing hosted run.** See row 6 for why no recent green run exists. |
| 5 | The owning specification's own claimed test evidence for this exact harness | `docs/PUBLIC-OWNED-DATA-API-V1.md`: "Scoped local execution of `public_native_rust_owned_data_sdk_v1` on Linux AArch64/Rust 1.88/Clang 14 passes nine selected tests... These results do not establish shared-context safety, full native support, hosted promotion or physical allocator settlement." | **Local evidence, as the spec itself already states.** Predates, or does not claim, the CI wiring found in row 4. |
| 6 | Whether a recent hosted CI run has actually exercised this harness successfully | Checked this session via `gh run list --workflow=ci.yml --limit 100`: **zero** of the last 100 completed CI workflow runs had conclusion `success` (mostly `cancelled`, superseded by rapid pushes from concurrent lanes, or `failure`). Inspected one representative recent run (commit `019fd931db`, 2026-09-19) job-by-job: every `verify-tests (integration-2)` and `(integration-3)` job (the shards containing this profile's and its sibling packages' tests) failed on all three OSes, but the failure that stopped each shard (`component_runtime_ci_contract`/`standalone_runner_is_pinned_private_and_outside_the_root_workspace`) is in an unrelated subsystem and occurs *before* the shard reaches `public_native_rust_owned_data_sdk_v1`, whose result is therefore unknown, not failing | **No current hosted evidence.** There is presently no green baseline run, at or near HEAD, that this ADR can point to for this profile's own harness. This is the most important honest gap in this table. |
| 7 | The separate general native-rust-interop-v1 profile's dedicated hosted job (`native-rust-sdk-v1`, NOT owned-data-api.v1) | Same commit `019fd931db`: `Public Native Rust SDK v1 (windows-latest)` completed **success**; `(ubuntu-latest)` and `(macos-latest)` completed **failure** in `public_native_rust_sdk_ci_contract` (an inventory-count meta-test, e.g. `left: 14, right: 10`) before the substantive `public_native_rust_sdk_v1` test target ran at all on those two OSes | **Hosted evidence, at a prior commit (`019fd931db`, not current HEAD), for a different profile than the one recommended here, 1-of-3 OSes fully green.** Cited only to show CI health context; does not back any claim about owned-data-api.v1. |
| 8 | External consumer execution against the packaged owned-data-api.v1 artifacts via a path dependency | `tests/release_archive_product_v1/owned_frame.rs`, invoked from `tests/release_archive_product_v1.rs:77` | The two tests that call it are `#[ignore]`d, requiring "an actual unpacked native release in absolute `SEMAPRAX_RELEASE_ROOT` and its exact `SEMAPRAX_RELEASE_COMMIT` label" (or additionally NODE/CLANG/SEMAPRAX_ARCHIVER/CARGO). **No evidence found or produced this session that this has been run recently, hosted or local; it is a manual, release-time procedure, not a routine gate.** |
| 9 | A packaged-**tarball** (not path-dependency) Rust consumer round trip, per issue #145 step 3's explicit requirement | `packaged_tarball_consumer_round_trips_with_preserved_lockfile_and_source_tied_checksum` (`tests/public_native_rust_sdk_v1.rs:778`) | Exists only for the **general native-rust-interop-v1 profile**, not owned-data-api.v1; gated behind `SEMAPRAX_REQUIRE_PUBLIC_NATIVE_RUST_SDK=1` (returns immediately otherwise -- a 0.01s "pass" without the guard is a false pass); the issue comment for `e0c7f192` reports it passed locally in 9.94s with the guard armed. **Local evidence at a prior commit, for a different profile than the one recommended here. No equivalent test exists yet for owned-data-api.v1.** |
| 10 | A packaged-tarball npm consumer round trip for this or any profile | `tests/frame_payload_product_v1/npm_installation.rs:60`, `tests/image_packaged_typescript_workflow_v1.rs:715` | Both `#[ignore]`d pending provisioned Node/npm/TypeScript. **No evidence, hosted or local, was found.** |
| 11 | Manual validation against a genuinely compiler-built package | Issue comment for `2ae8a968`: "validated by hand against a genuinely compiler-built package (`examples/frame-payload-project` via `target/debug/semaprax-full`)" | **Local, one-off, prior commit, by hand.** Not re-run this session; not a repeatable gate. |

Row 6 is the one this ADR most wants a maintainer to weigh: the tool that
would gate publication is solid (rows 1-2), but the profile's own generated
Rust SDK harness has no recent confirmed hosted pass, and the shard structure
means one unrelated subsystem's break can silently prevent it from ever
running. That is a real gap between "the tests exist and are wired in" and
"the tests are known to pass."

## What approving this commits the maintainer to

- **Rebuild-and-revalidate cadence.** Nothing here re-runs automatically on a
  schedule. Every dependency, toolchain, or compiler-output change to
  owned-data-api.v1 requires someone to re-run `prepare` + `check` and, before
  trusting the result, confirm `public_native_rust_owned_data_sdk_v1` and the
  `native-rust-sdk-v1`/`verify-tests` jobs are actually green at that commit
  -- not merely wired in.
- **What breaks the claim silently.** Because the crate version is fixed at
  `0.1.0` and compatibility rides on the descriptor digest instead, a
  consumer pinning by Cargo semver gets no protection from a breaking change;
  only the descriptor digest changing signals it. Approving this without
  requiring real semver (Open question 2) means every future regeneration is,
  from a semver consumer's point of view, silently "the same version."
- **CI-ordering obligation.** The `verify-tests` shard aborts at the first
  failing target, so an unrelated subsystem's regression can prevent this
  profile's own tests from running at all without failing loudly as *this
  profile's* failure. Trusting this route going forward means either fixing
  that ordering (Open question 6) or manually confirming, per release, that
  the specific target actually executed and passed -- not just that the
  overall job did not fail for some other reason.
- **Toolchain honesty.** The generated crate declares `rust-version = "1.85"`
  but has not been shown to build end to end under exactly 1.85.0 anywhere in
  this repository. Approving this route without resolving that (Open
  question 3) means shipping an MSRV claim nothing currently verifies.
- **Irreversibility once real publication happens.** This ADR proposes no
  registry write, but if a later, separately approved step does publish, a
  published version can never be deleted or overwritten on crates.io or
  npmjs.org; only rollback via a new, superseding version is possible
  (already the policy drafted in
  `docs/GENERATED-PACKAGE-PUBLICATION-DECISION-DRAFT-V1.md`).
- **Registry identity and credentials remain a separate, later decision.**
  Approving this ADR does not select an npmjs.org scope, a crates.io
  publisher account, or provision `NPM_TOKEN`/`CARGO_REGISTRY_TOKEN`; those
  are Open questions 4 and are explicitly out of scope until asked for again.

## What is explicitly NOT proposed

- **No registry write of any kind**, in any mode. `scripts/generated-package-release.py`
  has no code path that performs one; this ADR does not ask for one to be
  added.
- **No signing.** Blocked on issue #168 and
  [docs/RELEASE-SIGNING-POLICY-V1.md](../RELEASE-SIGNING-POLICY-V1.md); this
  package remains unsigned and its checksum manifest is an integrity value,
  not a signature or provenance claim.
- **No release or tag creation.** This is release-preparation tooling, not a
  release step.
- **No generic-ABI packages.** Those remain gated on SPX-AI-042 (#144) per
  issue #145's own scope boundary; nothing here changes which Project profile
  is admitted or grants any generic package new authority.
- **No npm package promotion** in this round, for the reasons given in
  Decision.
- **Box 3's "clean-install executable evidence" does not exist today for
  this profile.** To be precise, rather than soft about it: there is no test,
  hosted or local, that installs the owned-data-api.v1 Rust package from a
  real tarball or registry artifact and runs it. The closest things that
  exist are (a) a path-dependency consumer test that is `#[ignore]`d and
  requires manual release-root setup (row 8), and (b) a tarball-consumer test
  that is real but belongs to a different generated-package profile and is
  itself gated and last known to pass only at a prior commit (row 9).
  Approving this ADR is a decision to build toward that evidence, not a
  claim that it already exists.

## Open questions the maintainer must answer

1. Approve owned-data-api.v1's Rust package as the first maintained
   generated-package route, with npm explicitly deferred? (yes/no)
2. Should a real, incrementing semver scheme replace the current fixed
   `0.1.0` literal before any publish is considered, given that compatibility
   currently rides on the descriptor digest instead? (require-real-semver /
   accept-fixed-version-plus-digest)
3. Should the generated crate's `rust-version = "1.85"` MSRV claim stand as
   is, or must it first be confirmed by an actual 1.85.0 end-to-end build
   before being called supported? (accept-as-is / require-1.85.0-build)
4. Which exact registry publisher identity (crates.io account/org and
   npmjs.org scope, if npm is later added) would own this package's name?
   (name a value, or "not yet")
5. Should `public_native_rust_owned_data_sdk_v1` be required to show a
   recent, specific, confirmed-green hosted run before this route is trusted
   for any support claim, given none currently exists? (yes/no)
6. Should the `verify-tests` shard be changed so that one target's failure
   does not prevent sibling targets in the same shard from running and
   reporting their own result? (yes/no)
7. Is a manual, `#[ignore]`-gated consumer check run by a human before each
   release acceptable ongoing box-3 evidence, or must an unconditional CI
   gate replace it first? (manual-acceptable / require-ci-gate)
8. Should npm support for the same profile be folded into this ADR once its
   `#[ignore]`d tests are unblocked, or should it get its own separate ADR
   with its own evidence table? (extend-this-adr / separate-adr)

## Maintainer decision

Recorded 2026-09-19. The maintainer approved the scope and delegated the eight
questions above with the instruction to decide by what is best for the language
long term. That constraint does most of the work below: in four of the eight, it
argues *against* claiming more than the evidence supports.

1. **Yes — Rust only, npm deferred.** A narrow route that is fully evidenced is
   worth more than a wide one that is half evidenced. A support claim is very
   cheap to make and very expensive to withdraw: once consumers depend on it,
   retracting it breaks them, so the first maintained route should be the one we
   are most certain of.
2. **require-real-semver, before any publish** (not before this ADR stands). The
   descriptor digest is the real compatibility signal *inside* this project, but
   no registry consumer can see it: Cargo's resolver, lockfiles and downstream
   automation all assume the version string orders releases and carries
   compatibility meaning. A fixed `0.1.0` tells every one of those tools
   something false. It is also self-defeating in practice — registries make
   versions immutable, so a second publish at `0.1.0` is simply refused. Keep
   the digest, and record it in metadata *alongside* a real version.
3. **require-1.85.0-build.** An unverified MSRV is a support claim with no
   evidence, which is the exact thing this repository's documentation invariant
   forbids. MSRV is load-bearing for consumers who pin toolchains, it is cheap
   to verify and expensive to be wrong about. Note this cannot be discharged on
   the current dev host (Homebrew Rust, no `rustup`), so it is a gate, not a box
   to tick today.
4. **Not yet.** No publish is proposed, and naming a registry identity now would
   imply an intent to publish that this ADR explicitly does not carry. This must
   be answered before any publish, and by a human.
5. **Yes — a specific, recent, confirmed-green hosted run is required before any
   support claim.** This is the load-bearing answer. The harness is genuinely
   wired into `verify-tests` across three operating systems and has still never
   been observed to pass. Treating wiring as evidence would set the worst
   available precedent for a language whose entire pitch is "meaning in,
   verified machine code out". Credibility here is the product.
6. **Yes — change the shard so one target's failure does not stop its siblings
   from running and reporting.** This is the highest-leverage answer in the
   list and its value extends well past this issue. Today a failure in an
   unrelated subsystem prevents this harness from *ever* reporting, which is
   precisely why question 5 has no evidence to point at. Fail-fast inside a
   shard destroys information: it converts "we do not know" into something
   easily misread as "it failed". Per-target reporting is how the project
   learns what actually passes.
7. **require-ci-gate.** A manual, `#[ignore]`-gated check run by a human before
   each release is the kind of gate that silently stops happening, and nothing
   detects that it stopped. This repository already holds the stronger line
   elsewhere — no feature is implemented without the completion matrix's
   executable gate — and box 3 should not be the exception.
8. **separate-adr.** Each support claim stays bound to its own evidence table.
   Folding npm into this document later would let it inherit Rust's evidence by
   adjacency, which is the same conflation this ADR exists to prevent.

**Consequence for issue #145.** Box 1 has its *decision* half. Its *gate* half,
and boxes 2 and 3, remain open on evidence rather than on judgment, and answer 6
names the concrete change that unblocks collecting it.

## Rejected alternatives

### Recommend Rust and npm together

Rejected because npm's only consumer-execution tests are `#[ignore]`d pending
provisioned Node/npm/TypeScript and no automated evidence -- hosted or
local -- of a real npm-tarball install exists for any generated package.
Bundling npm into this decision would attach box 3's support claim to a
route with zero install evidence.

### Recommend the general native-rust-interop-v1 SDK instead of owned-data-api.v1

Rejected because, while that profile has stronger hosted-CI and
tarball-consumer coverage (rows 7 and 9), the existing release-preparation
tool (`scripts/generated-package-release.py`) was built specifically around
owned-data-api.v1's file inventory, and the issue asks for one deliberately
chosen profile. A maintainer who wants the scalar SDK promoted too should
treat that as a separate, independently evidenced decision rather than
folding two different generated-package identities into one support claim.

### Treat the existing decision draft as sufficient and skip a formal ADR

Rejected because the issue's own guardrails ask that a design like this be
"submitted for independent maintainer review" in a form a maintainer can
accept or reject cleanly, and this repository's house convention for that is
an ADR under `docs/decisions/`, not a standalone spec-shaped draft. The draft
remains useful background detail and is retained, not deleted.
