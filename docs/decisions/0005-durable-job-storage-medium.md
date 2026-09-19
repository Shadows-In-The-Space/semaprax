# ADR 0005: Durable job storage uses the workspace generation substrate, not a bundled SQL driver

Audience: maintainers deciding GitHub issue #192's storage dependency;
job-runtime and platform contributors.

- Status: **Accepted on 2026-09-19, by the repository maintainer (Kevin,
  `kevin.riedl@wavect.io`, `wavect/semaprax` owner).** The maintainer
  delegated this decision to the implementing agent under one stated
  constraint: choose whatever is best practice and best for the language long
  term, including competitive advantage. What follows is that delegation
  exercised, written down by the agent as scribe rather than self-approved.
- Related: #192 (this decision), #190 (typed SQLite and PostgreSQL access,
  closed with its driver decision recorded as `HUMAN_BLOCKED`), ADR 0002
  (managed workspace generations).

## The decision that was blocked

#192's durable-jobs work is complete except for one required test: a
database-backed adapter for enqueue plus application state.
`src/database_fixture.rs` is an in-memory `BTreeMap`, and the workspace has no
SQL crate. Its dependency #190 closed **without** shipping a physical driver,
leaving the choice open. Multi-process concurrency is untested for the same
reason: there is no shared durable medium for separate processes to contend
over.

## Decision

**Implement durable jobs on this repository's own atomic-generation substrate
as the default medium, behind a sealed `JobStore` adapter seam. Do not add a
SQL driver to the default build.** A vendored SQLite adapter remains
*possible* and *additive* behind that seam, off by default, and is explicitly
not required to close #192.

## Why not a bundled SQL driver in the default path

1. **It contradicts the capability invariant.** `rusqlite` with the `bundled`
   feature compiles vendored C and requires `unsafe` FFI. Eight crates in this
   workspace declare `unsafe_code = "forbid"`. PostgreSQL is worse for this
   purpose: it needs a running server and network authority, which the
   compiler and generated code are forbidden to acquire ambiently.
2. **It expands the supply chain and the build matrix** — a C toolchain on
   Linux, macOS and Windows MSVC — to obtain a property this repository can
   already express.
3. **SQLite's durability defaults mislead.** Commits are not durable under
   default settings; `synchronous=NORMAL` in WAL mode permits losing recently
   acknowledged writes after an OS or power failure, and only
   `synchronous=FULL` requests commit synchronisation. Adopting a dependency
   and *still* having to reason carefully about fsync buys less than it
   appears.

## Why the existing substrate is the right medium

ADR 0002 already publishes **one complete immutable generation through
`ACTIVE`** (`.semaprax-workspace/ACTIVE`): content staged, then pivoted by a
single atomic rename. That is exactly the canonical durable-commit pattern —
atomic rename as a single, well-defined commit point — and it is already
crash-safe, already deterministic, and already load-bearing in this codebase.

Building durable jobs on it means job state inherits the properties the
language already guarantees: deterministic replay, failed transactions leaving
authoritative state unchanged, and no new ambient authority. It also supplies
the shared medium that multi-process concurrency testing currently lacks, so
that gap closes with the same work.

## The honest durability caveat, recorded so it is not rediscovered

An append-only design plus atomic rename is **crash-friendly but not
automatically durable**. To acknowledge a job as durably accepted the
implementation must: write the complete record to a staging file, flush it,
fsync the file, rename it into place on the same filesystem, and then sync the
containing directory entry where the platform supports it — only then
acknowledge. Group-commit (batch appends, one fsync) is the accepted way to
keep that affordable.

Whatever durability level is chosen must be **stated in the profile
documentation**, not implied. "Do not describe private, local, proof-only ...
evidence as ... production support" applies to durability claims too: a store
that has not fsynced has not committed, and must not report that it has.

## Why this is a competitive advantage

"Durable background jobs, scheduling, retries and idempotency — **with no
database to run**" is a genuinely differentiating claim, and it is the same
move SQLite itself made one level down. Every comparable runtime requires the
user to provision Postgres or Redis before a job can survive a restart. A
language whose workspace substrate is already transactional can offer durable
jobs as a property of the platform rather than an integration.

It also keeps the `--locked --offline` CI story intact: no service to start, no
container to pull, no credentials to hold.

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
