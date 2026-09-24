# v0.6.0 hosted gate status

Status: exact-job observations only; the release gate is not green and v0.6.0
is not published or signed.

Audience: release reviewers, maintainers, and readers checking hosted claims.

## Current tag run

At 2026-09-24 20:53 UTC, the [new v0.6.0 tag run](https://github.com/wavect/semaprax/actions/runs/36047757697)
for exact commit `ac2ce08666a66527b614fc7c10982cdab0026a38` had 26
successful jobs, one failed job, and 36 jobs without a conclusion. The
[Rust 1.88 integration-2 job](https://github.com/wavect/semaprax/actions/runs/36047757697/job/107796106524)
failed because `tests/source_locked_contracts.rs` found four source-text
readers that had lost coverage after module splits. A focused local repair in
a newer checkout restores those readers; it is **not** part of this tag. The
remaining jobs and the aggregate release gate still need their own outcomes.
No partial job success makes the tag releasable.

## Earlier tag run

At 2026-09-24 19:12 UTC, the [earlier tag-push CI run](https://github.com/wavect/semaprax/actions/runs/36028102754) for `v0.6.0` was still running against exact commit
[`32d45f30adeaa7709f93efdea60cea79a66491d6`](https://github.com/wavect/semaprax/commit/32d45f30adeaa7709f93efdea60cea79a66491d6).
Thirty-five jobs had concluded successfully, four had failed, one had reached
its 90-minute job timeout, and the remaining jobs had not concluded. These
successes are hosted evidence for their named job scopes **at that old commit**.
They neither certify newer `main` nor satisfy the aggregate release gate.

Selected completed hosted job evidence:

| Narrow observation at `32d45f30` | Successful exact jobs |
| --- | --- |
| Public generic ownership milestone on three runners | [Ubuntu](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240795), [macOS](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240688), [Windows](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240924) |
| Public Native Rust owned-data SDK v1 on three runners | [Ubuntu](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240676), [macOS](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240977), [Windows](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240721) |
| Project Manifest v1 on three runners | [Ubuntu](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730241227), [macOS](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730241122), [Windows](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730241078) |
| Project Product Acceptance v1 on three runners | [Ubuntu](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730241216), [macOS](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730241201), [Windows](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730241102) |
| Platform/runtime checks | [Android JNI x86_64](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730241067), [Android JNI arm64](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730241385), [Swift/iOS application](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240755), [desktop macOS](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240476), [desktop Windows](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240838) |
| Bounded release and quality checks | [Release claim reconciliation](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240683), [Python harness self-tests](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240766), [dependency policy](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240726), [callable-host ASan/UBSan](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240722) |

The old-head run separately reports [STD-08 documentation](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240243), [private Component runtime](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240565), and two [Ubuntu](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730241448)/[Rust 1.88](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240813) `integration-2` failures; the corresponding fixes are on newer `main` and have only focused local verification so far. [GEN-05B](https://github.com/wavect/semaprax/actions/runs/36028102754/job/107730240731) reached its former 90-minute job limit, not a passing result; newer `main` allows 240 minutes without removing checks. A corrected exact-tag run must test all of these changes together.

No release artifacts, provenance signatures, attestation bundles, publication,
or independent release verification are established by these partial jobs.
The [release process](RELEASE-PROCESS.md) and [signing policy](RELEASE-SIGNING-POLICY-V1.md)
retain their full-gate and cryptographic evidence requirements. [Issue #289](https://github.com/wavect/semaprax/issues/289)
remains open.
