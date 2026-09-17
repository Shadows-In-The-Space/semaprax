# Windows doctor confinement and settlement contract v1

Status: **code lands with this revision, and it is unexecuted and
untypechecked on every host that authored it.** Every execution claim in this
document is `HUMAN_BLOCKED: needs a Windows host` -- both authoring sessions
ran on macOS arm64 with no `rustup`, no `*-pc-windows-*` target, and no
Windows toolchain, and no cross-compilation or emulated substitute is treated
as Windows evidence anywhere below. This revision adds the confinement
primitive's Win32 wiring (`#[cfg(windows)]`, never compiled here) plus its
host-independent sealed-capsule, admission-ordering, and settlement logic
(compiled and tested on every host this crate builds on, this one included).
See [Current state](#current-state-unchanged-by-the-first-revision) for
exactly what changed and what a Windows-capable session must still verify.

Audience: release engineers, platform maintainers, and security reviewers
with access to a real Windows host or a Windows CI runner.

The macOS half of this split is
[DOCTOR-PRODUCTION-PROVISIONER-MACOS-V1](DOCTOR-PRODUCTION-PROVISIONER-MACOS-V1.md),
which does carry real local execution evidence.

## Why the first revision had no accompanying code, and why this one does

[DOCTOR-PRODUCTION-PROVISIONER-V1](DOCTOR-PRODUCTION-PROVISIONER-V1.md)
states that "macOS and Windows need separate native confinement and
settlement contracts" and that "Linux evidence never promotes those hosts." A
prior session on this repository already established the adjacent principle
this document holds to: it "correctly refused to substitute a mingw
cross-compile for real Windows evidence, reasoning it would be 'weaker
evidence dressed as stronger'." The document's first revision extended that
same refusal one step earlier, to authorship, on the reasoning that shipping
unverified `unsafe` FFI into `windows.rs`/`windows/launch.rs` -- files that
already compile and pass on real Windows CI today
(`.github/workflows/ci.yml`'s `windows-2025` matrix legs) -- risked silently
breaking a currently-green Windows build with code nobody in that session
could check.

This revision reaches a different conclusion for the same host constraint,
for two reasons the coordinating session judged sufficient to proceed:

1. The new Win32 wiring lands in a **new, standalone module**
   (`doctor::windows_confinement`, mirroring `doctor::darwin_confinement`'s
   existing shape), not in `windows.rs`/`windows/launch.rs` themselves. Those
   two files, and the ordinary `--version` probe they implement, are
   byte-for-byte unchanged by this revision -- the currently-green Windows CI
   legs that build and run them are not touched by anything this revision
   adds.
2. Every symbol this revision's Win32 code calls -- every function
   signature, struct field, and constant -- was cross-checked against the
   exact vendored `windows-sys = "=0.61.2"` source this crate's `Cargo.toml`
   already pins, using only the `windows-sys` features that `Cargo.toml`
   (outside this session's lease) already enables. That is real diligence,
   raising confidence the new module compiles; it is **not** a substitute for
   a Windows toolchain actually compiling it, and this document does not
   claim otherwise anywhere below.

The `Cargo.toml` constraint from the first revision still holds: the
AppContainer filesystem-confinement route needs `Win32_Security_Isolation`,
not enabled today and outside every session's lease so far, so this revision
implements the restricted-ACL scratch-root alternative instead -- see
[Filesystem confinement](#3-filesystem-confinement).

## Current state (unchanged by the first revision; extended by this one)

`crates/semaprax-native-rust-interop-platform-sys/src/doctor/windows.rs` (296
lines) and `windows/launch.rs` (221 lines) still only implement the *ordinary
probe's* launch path, exactly as the first revision described: a process
created suspended (`CREATE_SUSPENDED`), assigned to a fresh,
non-breakaway-eligible job object (`CreateJobObjectW` +
`SetInformationJobObject` with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) via
`AssignProcessToJobObject` *before* `ResumeThread` lets any target code run,
with settlement observed through
`QueryInformationJobObject(JobObjectBasicAccountingInformation)`'s
`ActiveProcesses` field reaching zero. Neither file is modified by this
revision.

Alongside them, `crates/semaprax-native-rust-interop-platform-sys/src/doctor/windows_confinement/`
now exists, reusing that same job-object *shape* without importing
`windows.rs`'s private types (exactly as `doctor::darwin_confinement` does not
import `doctor::unix::launch::darwin`'s private types):

- `capsule.rs` -- host-independent structural sealed-capsule body parser (no
  Win32 call; compiles and its hostile-input tests run on every host).
- `refusal.rs` -- host-independent, order-enforcing admission classifier (no
  Win32 call; compiles and its ordering tests run on every host).
- `settlement.rs` -- host-independent sticky settlement state machine (no
  Win32 call; compiles and its tests run on every host).
- `primitive.rs` -- `#[cfg(windows)]` restricted token, tightened job object,
  ACL'd scratch root, sealed-capsule-gated suspended spawn, and settlement
  observation. Never compiled or executed on this authoring host; see its own
  module documentation for the exact simplifications it makes and the
  specific claims it does and does not make about itself.

This is still a **standalone confinement primitive**, not the production
provisioner: it is not wired into any ordinary CLI route or into
`provisioned_doctor_*`, per the issue's explicit request.

## Confinement primitive (implemented; unexecuted and untypechecked so far)

Windows has no namespace or cgroup-v2 equivalent. The three building blocks
this contract proposed, all already partially present in `windows-sys`'
enabled feature set (`Win32_Foundation`, `Win32_Security`,
`Win32_Storage_FileSystem`, `Win32_System_JobObjects`,
`Win32_System_Threading`, `Wdk_Foundation`, `Wdk_Storage_FileSystem`) or one
feature away from it, are now implemented as described below in
`crates/semaprax-native-rust-interop-platform-sys/src/doctor/windows_confinement/primitive.rs`.
No `windows-sys` feature was added; every symbol used is one the enabled
feature set already provides.

### 1. Job-object limits, tightened

Implemented as `primitive::tightened_job`, which builds its own job object
(distinct from `windows/launch.rs`'s, per the "standalone primitive" scope
above) and sets:

- `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` with `BasicLimitInformation.ActiveProcessLimit`
  set to a small fixed bound (one, for a tool invocation with no expected
  descendants; the doctor collector's existing hostile-input philosophy would
  treat a tool that spawns a second process as something to *observe and
  reject*, not silently accommodate). A limit violation terminates the whole
  job, which is the Windows analog of the Linux contract's
  `memory.oom.group = 1`: an overshoot kills the whole scope rather than
  refusing cleanly mid-invocation.
- `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, so a crashing tool cannot
  leave a debugger-attachable faulted process alive inside the job.
- A `JOBOBJECT_BASIC_UI_RESTRICTIONS` call (`SetInformationJobObject` with
  `JobObjectBasicUIRestrictions`) denying `JOB_OBJECT_UILIMIT_HANDLES`,
  `JOB_OBJECT_UILIMIT_READCLIPBOARD`, `JOB_OBJECT_UILIMIT_WRITECLIPBOARD`,
  `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS`, `JOB_OBJECT_UILIMIT_DESKTOP`,
  `JOB_OBJECT_UILIMIT_DISPLAYSETTINGS`, `JOB_OBJECT_UILIMIT_GLOBALATOMS`,
  and `JOB_OBJECT_UILIMIT_EXITWINDOWS`.

All of the above are exact fields/constants of `Win32_System_JobObjects`,
already an enabled feature; no `Cargo.toml` change was needed.

### 2. A restricted token

Implemented as `primitive::restricted_token`, narrower than first proposed:
it calls `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` and empty
disable/delete/restrict lists (not the fuller "also disable the caller's own
logon SID" refinement this document originally proposed). That fuller
refinement needs walking the calling token's `TokenGroups` to find the
`SE_GROUP_LOGON_ID` entry -- a variable-length structure this session judged
too easy to get subtly wrong with no way to compile-check it, let alone run
it. `DISABLE_MAX_PRIVILEGE` alone is still a real, meaningful restriction
(the resulting token holds no privileges at all), and the logon-SID
refinement is left as an explicit follow-up for a Windows-capable session,
recorded in `primitive.rs`'s own module documentation. `Win32_Security` is
already an enabled feature; no `Cargo.toml` change was needed.

The primitive uses `CreateProcessAsUserW`, not `CreateProcessWithTokenW`: the
former was judged to have the more directly verifiable calling convention
against the vendored source for this exact use (a token this process itself
just created, not one obtained through a separate logon).

### 3. Filesystem confinement

This session picked the **restricted-ACL scratch root** design, not an
AppContainer profile, exactly along the line the first revision drew:
`Win32_Security_Isolation` (needed for `CreateAppContainerProfile`) is still
not an enabled `windows-sys` feature, and `Cargo.toml` is still outside every
session's lease so far. Implemented as `primitive::confined_scratch_root`:
one fresh directory per invocation, with a DACL built from `InitializeAcl` +
`AddAccessAllowedAceEx` granting only the restricted token's own user SID
(read via `GetTokenInformation(TokenUser)`) `FILE_GENERIC_READ |
FILE_GENERIC_WRITE | DELETE`; no other principal is listed, which is an
implicit deny under Windows DACL evaluation. The tool's working directory and
its `TEMP`/`TMP` environment variables are confined to this directory
(`primitive::forced_environment`). This needs no `windows-sys` feature beyond
`Win32_Security`, already enabled.

This session did **not** verify whether an inheritable ACE from
`scratch_root`'s own parent directory can still additively grant access
alongside this explicit DACL; `primitive.rs`'s doc comment on
`confined_scratch_root` flags this and suggests `SE_DACL_PROTECTED` as the
fix if a Windows-capable reviewer confirms it is needed. Output capture is
also file-based (two fixed-name log files inside the same ACL'd directory)
rather than the pipe-based, attribute-list-restricted handle inheritance
`windows/launch.rs` uses for the ordinary probe -- a deliberate simplification
to keep the new unsafe surface reviewable without a toolchain, recorded in
`primitive.rs`.

## Sealed input and process handoff

[DOCTOR-SEALED-INPUT-V1](DOCTOR-SEALED-INPUT-V1.md)'s sealed-carrier concept
(`F_SEAL_*` on a Linux memfd) has no Windows equivalent primitive at the OS
level; the closest analog remains an anonymous, unnamed file mapping
(`CreateFileMappingW` with `NULL` name and no `FILE_MAP_WRITE` reopen path
after initial population), and this revision does not implement it -- that
half of the sealed-input contract (the immutable carrier itself) is still
open, exactly as the first revision left it.

What this revision does implement, in
`crates/semaprax-native-rust-interop-platform-sys/src/doctor/windows_confinement/capsule.rs`,
is the **structural decode of a capsule's body fields once bytes are in
hand** -- magic, version, architecture, target, role mask, selector, and the
five fixed-size artifact records -- byte-for-byte identical in constants,
field order, and validation rules to `semaprax-doctor-capsule` 0.1.0's private
body-decoding stage (`crates/semaprax-doctor-capsule/src/lib.rs`,
`parse_signed`). It deliberately does **not** verify the release Ed25519
signature that crate's `parse_signed` requires before a capsule may be
trusted: `semaprax-doctor-capsule` is a `cfg(target_os = "linux")`-only
dependency in this crate's `Cargo.toml` today, a file outside every session's
lease so far, so a Windows build cannot yet call it. A `CapsuleBody` result
from this module is explicitly **not** a trust decision (see the module's own
documentation and its `unverified_signature` field, which is copied out but
never checked). This exists so the admission ordering in `refusal.rs` and
this crate's own hostile-input tests have real capsule structure to refuse
against, on any host, today; a Windows-capable session with `Cargo.toml` in
its lease should add `semaprax-doctor-capsule` as a `cfg(windows)` dependency
too and delete this module's body decoder in favor of calling that crate's
`parse_signed` directly, rather than let the two decoders drift.

## Settlement contract

The same four-outcome shape this repository's macOS contract uses is now
implemented in
`crates/semaprax-native-rust-interop-platform-sys/src/doctor/windows_confinement/settlement.rs`,
for consistency across both non-Linux platforms, though the two do not share
an implementation:

```rust
enum Settlement {
    Completed,
    Failed(FailureReason),      // ExitCode(u32) | job-limit-violation
    Cancelled,                  // supervisor deadline fired
    Uncertain(UncertainReason), // wait/query failure, or ActiveProcesses > 0
                                 // after the leader is observed to have exited
}
```

**Settled** for a Windows job object means: `WaitForSingleObject` on the
leader process handle returns `WAIT_OBJECT_0`, *and* a subsequent
`QueryInformationJobObject(JobObjectBasicAccountingInformation)` reports
`ActiveProcesses == 0` -- mirroring the existing ordinary-probe `Child::settle`
in `windows.rs`, which already performs exactly this check
(`accounting.ActiveProcesses == 0`) after `TerminateJobObject`. This document's
one addition to that existing logic is the *sticky, four-way* outcome
distinction: the current ordinary probe only distinguishes "settled" from
"abort the whole harness process" (`std::process::abort()` on any observation
failure), which is correct for a bounded developer-machine probe but is not
the same as recording `Completed` vs `Failed` vs `Cancelled` vs `Uncertain` as
data a caller can inspect and act on differently, per this repository's
non-negotiable invariant that "a settlement or concurrency model is proof
data, not permission to perform a physical finalizer." A production
provisioner needs to report *which* of the four happened, not merely succeed
or abort the whole process.

Failure selection is sticky here exactly as macOS's `StickySettlement`
enforces, via the same `select`/`resolve` shape in `settlement.rs`'s own
`StickySettlement`: once `Failed`, `Cancelled`, or `Uncertain` is selected, no
later observation -- including a job-object accounting reread ostensibly
proving `ActiveProcesses == 0` -- may replace it with `Completed`. This
state-machine logic has no Win32 dependency and its sticky-selection tests run
on every host this crate builds on; `primitive::settle_confined`
(`#[cfg(windows)]`, unexecuted here) is the code that actually observes a real
job object and drives it.

## Proposed gate workflow (not landed; `.github/workflows/**` is out of scope
## for this authoring session)

Unlike the macOS contract, this document proposes a `workflow_dispatch`-only
gate, per the issue's explicit request, because the confinement primitive
above -- once implemented -- mutates job-object limits, restricted tokens,
and possibly an AppContainer profile or ACL'd filesystem root, none of which
this authoring session can characterize as non-destructive to a shared runner
without real execution evidence. The proposed shape mirrors
`.github/workflows/doctor-provisioned-linux.yml`:

```yaml
name: Doctor provisioned Windows gate

on:
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: doctor-provisioned-windows
  cancel-in-progress: false

jobs:
  doctor-provisioned-windows:
    name: Windows offline doctor lifecycle (provisioned)
    runs-on: windows-2025
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          fetch-depth: 1
          filter: blob:none
          fetch-tags: false
          lfs: false
      - uses: dtolnay/rust-toolchain@6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772 # master
        with:
          toolchain: 1.97.1
      - name: Prove the gate refuses absent provisioning
        run: python scripts/doctor-provisioned-windows-gate.py --self-test
      - name: Run the confinement primitive's hostile-input corpus
        run: cargo test --locked --offline -p semaprax-native-rust-interop-platform-sys --lib doctor::windows_confinement
```

`scripts/doctor-provisioned-windows-gate.py` does not exist yet; it should be
authored analogous to `scripts/doctor-provisioned-linux-gate.py`'s
`--self-test`/pure-decision-logic pattern (fail-closed, never a skip, and
self-testable on any host including this one) by whoever implements the
primitive above, since its exact precondition list depends on which
filesystem-confinement design (restricted ACL vs AppContainer) is chosen.
Neither the workflow file nor the gate script is added by this document; both
are specified here as the exact delta a maintainer should land.

## Acceptance criteria status

| Criterion | State |
|---|---|
| Versioned Windows contract, cross-referenced from V1 | met |
| Confinement primitive exists in the owning crate | implemented in `doctor::windows_confinement::primitive`; **`#[cfg(windows)]`, never compiled or run on any host that has touched it** -- see [Nonclaims](#nonclaims) |
| Sealed-capsule consumption | structural body decode only (`doctor::windows_confinement::capsule`, host-independent, tested on every host); signature verification still needs `semaprax-doctor-capsule` as a `cfg(windows)` `Cargo.toml` dependency, outside every session's lease so far |
| Hostile-input tests for the host-independent parts | 29 tests across `capsule`, `refusal`, and `settlement` pass on this authoring host (macOS arm64); `cargo test -p semaprax-native-rust-interop-platform-sys --lib doctor::windows_confinement` |
| Hostile-input tests for the Win32 primitive itself | not attempted: needs a live process, a real job object, and a real token -- `HUMAN_BLOCKED: needs a Windows host` |
| Fail-closed gate authored and run | proposed only (workflow YAML embedded above); **never run** |
| Linux, macOS, or existing job-object evidence never cited as Windows proof | met |
| `docs/COMPLETION-MATRIX.md` WP-05 promoted for Windows | not done; not claimed |

## Nonclaims

This contract does not: claim that `doctor::windows_confinement::primitive`
has been compiled, type-checked, or executed anywhere -- every symbol it
calls was cross-checked by hand against the vendored `windows-sys` source,
which raises confidence but is not a substitute for a Windows toolchain
actually building it; claim the existing ordinary-probe job-object
confinement in `windows.rs` as evidence of production-grade sandboxing (it
confines process *lifetime*, not filesystem or network access, and was not
designed as a security boundary); claim Linux or macOS evidence proves
anything about Windows; claim that this revision's own host-independent test
pass (`capsule`, `refusal`, `settlement`, run on macOS arm64) is Windows
execution evidence of any kind -- it proves only that logic with no Win32
dependency behaves as designed, nothing about the primitive that actually
touches a job object, a token, or the filesystem; run on a cross-compiled or
emulated target as a substitute for real Windows execution; wire any new path
into the CLI; or promote `docs/COMPLETION-MATRIX.md` WP-05 for Windows. It
also does not claim that `CreateRestrictedToken`'s returned token carries
sufficient access rights for the later `GetTokenInformation`/
`CreateProcessAsUserW` calls the primitive makes on it, or that an explicit
DACL on a freshly created directory is not additively widened by an
inheritable ACE from its parent -- both are flagged as open, unverified
questions in `primitive.rs`'s own doc comments for a Windows-capable reviewer
to resolve. It records the design decisions and now the code a Windows-capable
session should review and verify, and the exact places (the restricted-token
refinement, sealed-capsule signature verification, the DACL-inheritance
question, hostile-input tests for the primitive itself, the gate script) that
still need real Windows execution to close.
