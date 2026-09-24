# Windows doctor confinement and settlement contract v1

Audience: release engineers, platform maintainers, and security reviewers
with access to a real Windows host or a Windows CI runner.

Status: **code lands with this revision; it is unexecuted on every host that
has touched it, but its `#[cfg(windows)]` source has one later hosted Windows
compilation witness.** Every *execution* claim in this document remains
`HUMAN_BLOCKED: needs a Windows host` -- both authoring sessions ran on macOS
arm64 with no `rustup`, no `*-pc-windows-*` target, and no Windows toolchain,
and no cross-compilation or emulated substitute is treated as Windows evidence
anywhere below. This revision adds the confinement primitive's Win32 wiring
plus its host-independent sealed-capsule, admission-ordering, and settlement
logic (compiled and tested on every host this crate builds on, this one
included). See [Hosted Windows compilation evidence](#hosted-windows-compilation-evidence-type-check-only)
and [Current state](#current-state-unchanged-by-the-first-revision) for the
exact, deliberately narrow evidence and remaining verification.

The macOS half of this split is
[DOCTOR-PRODUCTION-PROVISIONER-MACOS-V1](DOCTOR-PRODUCTION-PROVISIONER-MACOS-V1.md),
which does carry real local execution evidence.

## Hosted Windows compilation evidence (type-check only)

The earlier "never compiled" statement is no longer accurate. Hosted
[run 35462242188](https://github.com/wavect/semaprax/actions/runs/35462242188)
checked out `7cab8aa8fa67d412fa82643ab8139cbd9eb00b43`, which includes the
Windows confinement module and `94adc21b`'s later
`GetCurrentProcess` import correction to `primitive.rs`. Its overall workflow
conclusion was failure for unrelated jobs, but the successful
[Public Native Rust SDK v1 (windows-latest) job 105948054658](https://github.com/wavect/semaprax/actions/runs/35462242188/job/105948054658)
compiled `semaprax-native-rust-interop-platform-sys` on Windows Server 2025
while running this exact command:

```text
cargo test --locked --offline -p semaprax-native-rust-interop-platform-sys --lib tests::windows_archive::windows_real_brepro_archive_round_trips_through_exact_admission -- --exact --nocapture --test-threads=1
```

The selected `tests::windows_archive` test caused successful library
compilation, which type-checks the `#[cfg(windows)]`
`doctor::windows_confinement::primitive` source present in that checkout. It
executed no `doctor::windows_confinement` function: it did **not** create a
restricted token, start a confined child, assign a job, apply an ACL, or
observe settlement. It is compilation evidence only, not a confinement or
hostile-input execution witness. `7cab8aa8` is an ancestor of the tree audited
for this update; no claim is made about a later unrun commit.

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
   raised confidence before a Windows toolchain compiled it. The later hosted
   compilation witness above now proves type-checking for that exact checkout;
   it remains **not** a substitute for executing the confinement primitive.

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
  observation. Never compiled or executed on this authoring host; it has the
  hosted Windows type-check witness above, but no execution witness. See its
  own module documentation for the exact simplifications it makes and the
  specific claims it does and does not make about itself.

This is still a **standalone confinement primitive**, not the production
provisioner: it is not wired into any ordinary CLI route or into
`provisioned_doctor_*`, per the issue's explicit request.

## Confinement primitive (implemented; hosted type-checked, unexecuted)

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
too easy to get subtly wrong before any Windows compilation, let alone runtime
execution. `DISABLE_MAX_PRIVILEGE` alone is still a real, meaningful restriction
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

## Windows runtime gate

The dispatch-only
[`.github/workflows/doctor-provisioned-windows.yml`](../.github/workflows/doctor-provisioned-windows.yml)
uses an ephemeral `windows-2025` runner and creates a fresh, explicit scratch
parent under `RUNNER_TEMP`. The gate fails when the host is not 64-bit Windows,
the parent is missing, nonempty, or a reparse point, Cargo fails, either named
test is filtered or ignored, or the test summary does not report both runtime
cases as passed. It never treats an absent prerequisite or a zero-test run as
a skip/pass.

`scripts/doctor-provisioned-windows-gate.py --self-test` checks the gate's
refusal and libtest-result parsing on any host; it provides no Windows runtime
evidence. `--plan` prints the exact two-test selector. The live selection runs
`windows_runtime_launches_restricted_child_inside_acl_scratch_and_settles_it`
and `windows_runtime_timeout_terminates_the_confined_job_and_settles_cancellation`.
Those tests launch the owning test executable through `confined_spawn`, inspect
the child's disabled privilege set and job membership/limits, read back the
scratch DACL and its SID, exercise the one-process job limit, observe a
successful settlement, and observe timeout cancellation.
Each live test captures then removes its exact child marker before settlement,
and requires the per-invocation scratch directory and provisioned parent to be
empty afterward. If the 600-second gate timeout fires on Windows, the gate
uses `taskkill /T /F` on Cargo's PID, waits for pipe/process settlement, and
verifies Cargo's PID is absent; inability to verify the direct process exit is
itself a gate failure. Descendants reparented before the post-kill process-list
check are not independently enumerated, so this is not a general descendant
quiescence proof.

The test capsule is deliberately structural fixture data with a placeholder
signature. The Windows primitive currently does not verify capsule signatures,
so these tests do not establish signed-capsule admission or production
provisioner support. The gate is dispatch-only; its first successful run is
still required before any Windows runtime result can be claimed.

## Acceptance criteria status

| Criterion | State |
|---|---|
| Versioned Windows contract, cross-referenced from V1 | met |
| Confinement primitive exists in the owning crate | implemented in `doctor::windows_confinement::primitive`; hosted Windows type-checked for exact checkout `7cab8aa8` in [job 105948054658](https://github.com/wavect/semaprax/actions/runs/35462242188/job/105948054658), but never executed -- see [Nonclaims](#nonclaims) |
| Sealed-capsule consumption | structural body decode only (`doctor::windows_confinement::capsule`, host-independent, tested on every host); signature verification still needs `semaprax-doctor-capsule` as a `cfg(windows)` `Cargo.toml` dependency, outside every session's lease so far |
| Hostile-input tests for the host-independent parts | 29 tests across `capsule`, `refusal`, and `settlement` pass on this authoring host (macOS arm64); `cargo test -p semaprax-native-rust-interop-platform-sys --lib doctor::windows_confinement` |
| Runtime tests for the Win32 primitive itself | authored for restricted-token child launch, job limits and membership, scratch ACL, descendant refusal, successful settlement, and timeout cancellation; not run on Windows in this change |
| Fail-closed gate authored and run | workflow and result-checking script authored; script self-test run locally; live Windows gate **not run** |
| Linux, macOS, or existing job-object evidence never cited as Windows proof | met |
| `docs/COMPLETION-MATRIX.md` WP-05 promoted for Windows | not done; not claimed |

## Nonclaims

This contract does not: claim that `doctor::windows_confinement::primitive`
has passed a Windows runtime gate. The hosted Windows compilation recorded above
type-checks only exact checkout `7cab8aa8`; it does not establish an execution,
confinement, token, job-object, ACL, filesystem, or settlement claim. Earlier
hand-checking against vendored `windows-sys` was diligence, not substitute
execution evidence. The new tests use an unverified-signature capsule fixture,
and do not close signed-input, independent hostile-corpus, descendant-tree, or
production-support requirements. Do not claim the existing ordinary-probe
job-object confinement in `windows.rs` as evidence of production-grade
sandboxing (it confines process *lifetime*, not filesystem or network access,
and was not designed as a security boundary); claim Linux or macOS evidence
proves anything about Windows; claim that this revision's own host-independent
test pass (`capsule`, `refusal`, `settlement`, run on macOS arm64) is Windows
execution evidence of any kind -- it proves only that logic with no Win32
dependency behaves as designed, nothing about the primitive that actually
touches a job object, a token, or the filesystem; run on a cross-compiled or
emulated target as a substitute for real Windows execution; wire any new path
into the CLI; or promote `docs/COMPLETION-MATRIX.md` WP-05 for Windows.

The newly authored runtime assertions have not yet run on Windows, so they do
not establish that `CreateRestrictedToken` returns a token with sufficient
rights for the later token-query/process-creation calls, that the protected
DACL survives creation with exactly the expected ACE, or that cancellation
leaves no descendant process. The remaining real-host work includes the
restricted-token refinement, signed-capsule verification, a broader hostile
corpus, descendant-tree cleanup evidence, and the first execution of the
dispatch-only gate.
