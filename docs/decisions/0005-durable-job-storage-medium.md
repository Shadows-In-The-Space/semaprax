# ADR 0005: Durable job storage uses the workspace generation substrate, not a bundled SQL driver

Audience: maintainers deciding GitHub issue #192's storage dependency;
job-runtime and platform contributors.

- Status: accepted on 2026-09-19 by the repository maintainer, who delegated
  the storage-medium choice to the implementing agent. This is a design
  decision, not evidence that a durable store has shipped.
- Related: #192 (this decision), #190 (typed SQLite and PostgreSQL access,
  closed with its driver decision recorded as `HUMAN_BLOCKED`), ADR 0002
  (managed workspace generations).

## Problem

Issue #192 still needs a test of enqueue and application state on a shared
durable medium. `src/database_fixture.rs` uses an in-memory `BTreeMap`, so it
cannot prove recovery or multi-process concurrency. Issue #190 closed without
a physical SQL driver.

## Decision

Use the repository's atomic-generation substrate as the default medium behind
a sealed `JobStore` adapter. Do not add a SQL driver to the default build. An
optional SQLite adapter may be added later; it is not required to close #192.

## Why not a bundled SQL driver in the default path

1. Bundled `rusqlite` adds vendored C and `unsafe` FFI to a workspace where
   eight crates forbid unsafe code. PostgreSQL also needs a server and
   explicit network authority.
2. A default driver expands the Linux, macOS, and Windows build matrix.
3. SQLite still needs a deliberate durability configuration; WAL with
   `synchronous=NORMAL` may lose recently acknowledged writes after a power
   failure.

## Why the existing substrate is the right medium

ADR 0002 publishes one complete immutable generation through `ACTIVE`. That
gives cooperating readers an atomic visibility point, not automatic
power-loss durability. A `JobStore` built on this pattern can reuse
deterministic replay and explicit authority while adding the fsync and
recovery rules jobs need. It would also provide a shared medium for
multi-process tests.

## Durability requirement

Atomic rename alone does not make an acknowledged job durable. Before a
durable acknowledgement, the implementation must write and flush the staged
record, fsync it, rename it on the same filesystem, and sync the containing
directory where supported. Group commit can amortize fsync cost.

The profile must state its durability level. An unfsynced store must not report
a durable commit.

## Operational benefit

The default path would need no separate database service, container, or
credentials, which keeps offline CI possible. This is a design benefit, not a
claim that restart-safe jobs are already available.

## Consequences

- `src/database_fixture.rs` stays an in-memory fixture for unit tests and stops
  pretending to be the durable path.
- The `JobStore` seam is the real deliverable: sealed, with the generation
  substrate as its first implementation, so a later vendored-SQLite adapter is
  additive and changes no caller.
- #192's "database transaction integration" criterion should be read against
  that seam. If the issue's author intends *specifically* a SQL engine, this
  ADR changes the criterion rather than satisfying it, and that re-scope must
  be stated on the issue rather than quietly assumed.
- Multi-process concurrency tests become possible and are therefore expected.

## What this ADR does not decide

- The on-disk record format for job state.
- Whether an optional SQLite adapter ships at all, and under which feature
  flag. It is permitted, not scheduled.
