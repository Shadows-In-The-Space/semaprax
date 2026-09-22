# AArch64 Linux offline doctor confinement tracking v1

Status: **in scope, tracked, and unexecuted on the proposed hosted runner.**
This is a separate AArch64 tracking contract, not an extension of the
x86-64-only [Provisioned Linux gate v1](DOCTOR-PROVISIONED-LINUX-GATE-V1.md).
It neither promotes WP-05 nor establishes hosted, physical-device, or general
production support.

Audience: release engineers, platform maintainers, and security reviewers.

Tracking issue: [#279](https://github.com/wavect/semaprax/issues/279).

## Scope decision

Linux AArch64 is in scope for the private production provisioner. The owning
[Provisioner v1](DOCTOR-PRODUCTION-PROVISIONER-V1.md#purpose-and-boundary)
states that its first implementation is native 64-bit little-endian Linux
x86-64 **and AArch64**. Its source-level admission also selects a closed,
default-deny syscall table for each native ABI. That implementation statement
does not make AArch64 evidence interchangeable with x86-64 evidence: the
existing x86-64 gate intentionally rejects AArch64, and its run can never
credit this contract.

Accordingly, this document commits AArch64 to separate tracking. A future
fully provisioned AArch64 gate must exercise the same twenty-six lifecycle
fixtures, through a native AArch64 package, real Clang/Node/Rust carrier, and
the architecture-specific closed policy. It must report an absent namespace,
cgroup, image, sealed input, real bundle, selector, or kernel prerequisite as
a failure rather than a skip. It must not change a syscall, open-flag, rlimit,
or capability allowance merely because a hosted run fails: a proposed widening
needs an observed real-binary behaviour and a negative control demonstrating
that the protected operation remains denied.

## Historical local evidence

Commit [`734e67af`](https://github.com/wavect/semaprax/commit/734e67af)
recorded one native AArch64 Linux 6.12 lifecycle run in Docker Desktop's Linux
VM on Apple Silicon. The worker, launcher, and collector were built and run as
native AArch64 binaries; this was not cross-compilation or emulation. It is
**local Docker-VM evidence**, not GitHub-hosted evidence and not
physical-device evidence. It was recorded at that commit and is not a claim
about the current head.

The run passed 24 of the 26 ignored lifecycle fixtures. It included the
zero-syscall spin sentinel
`doctor::offline_worker::tests::lifecycle::post_exec_capabilities_and_supervisor_death_are_observed_externally`,
which is relevant context for the separate x86-64 investigation but proves
nothing about that host's unresolved real-distribution failure.

The two remaining fixtures were not confinement passes and were not silently
skipped:

- `doctor::offline_worker::tests::provisioned_real_clang_node_rust_distributions`
- `real_launched_handoff::production_launcher_reports_all_roles_from_provisioned_real_distributions`

They failed fast because that local run supplied neither the required real
Clang/Node/Rust bundle nor its selector and independent expected details. Their
absence is an explicit unresolved contracted exclusion, not a result from
which success can be inferred. The checked-in local reproduction script keeps
the twenty-four-case partial selection separate and labels the missing
real-distribution precondition; it is not a replacement for the full gate.

## Hosted runner candidate

`.github/workflows/doctor-provisioned-linux-aarch64.yml` is a dispatch-only,
unexecuted candidate for a GitHub-hosted `ubuntu-24.04-arm` runner. It is not a
CI-required job, has no push or pull-request trigger, and has no
`continue-on-error`. The checked-in partial driver has exactly two named
`--skip` exclusions: `doctor::offline_worker::tests::provisioned_real_clang_node_rust_distributions`
and `real_launched_handoff::production_launcher_reports_all_roles_from_provisioned_real_distributions`.
Those exclusions define its twenty-four-case boundary. The driver then runs
both excluded fixtures individually to observe each missing-real-bundle
precondition. Each probe is required to fail with its exact missing-bundle or
missing-selector reason: an unexpected pass or another failure is itself a
gate failure, and the expected nonzero results are not confinement passes.
Every selected lifecycle command is otherwise unmasked and
fail-fast: an
unannounced selected-case skip or mask is a contract failure.
The job first proves that its native host is Linux AArch64, fetches the locked
dependency graph before setting Cargo offline, and then invokes that driver.
Missing user namespaces, Cargo, a native AArch64 host, dependencies, or any
unmasked selected lifecycle assertion makes the job fail. A runner label is
not an attestation; the driver re-observes the host properties it can.

The candidate deliberately does **not** call itself a full AArch64 gate. It
does not package a signed AArch64 release or invent the missing real carrier,
so it cannot resolve the two excluded fixtures. Its first dispatch answers
only whether this particular hosted image can execute the specified
twenty-four-case native tracking probe. A passing dispatch would remain hosted
partial evidence, not a production or WP-05 promotion. A failed dispatch is
evidence of a failure only after the job log identifies the exact failed
precondition or fixture; it is never permission to widen the policy.

## Completion boundary

This issue's historical-recording and runner-contract tranche is complete when
the checked-in sources preserve the scope decision and runner candidate. The
runtime portion remains open: dispatch the candidate, provision a real native
carrier and signed release path, run all twenty-six fixtures, and either close
the two named real-distribution cases or revise this contract with a reviewed,
explicit exclusion. No result from the x86-64 gate can perform those steps.

## Nonclaims

This document does not claim a hosted run, a current-head run, a physical
device, a successful full AArch64 gate, an ordinary CLI route, an authenticated
build host, or production readiness. It does not broaden any x86-64 policy or
permit a future AArch64 policy change without direct evidence and a surviving
negative control.
