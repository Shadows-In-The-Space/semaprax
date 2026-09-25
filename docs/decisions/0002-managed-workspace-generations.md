# ADR 0002: Managed immutable generations and an ACTIVE pivot

Audience: maintainers and compiler contributors.

- Status: accepted
- Date: 2026-08-11

## Context

RFC 0001 requires a successful multi-file transaction to publish all verified
changes together. Renaming source files one by one would let a reader see a
mixture of old and new files. The existing single-file A0 route cannot be
widened without changing its contract.

## Decision

Semantic Workspace Transaction v1 keeps immutable source generations under
`.semaprax-workspace`. Each generation is named by the digest of its canonical
manifest. A single `ACTIVE` file selects one generation. Cooperating readers
take a shared lock and authenticate that selection. Writers take an exclusive
lock, publish a complete candidate without replacement, and switch `ACTIVE`
only after final checks.

Initialization creates generation zero and the first `ACTIVE`. Ordinary apply
never rewrites original source files. Exact wire formats, limits, diagnostics,
and exclusions are in
[Semantic Workspace Transaction v1](../SEMANTIC-WORKSPACE-TRANSACTION-V1.md).

## Consequences

- Cooperating managed readers observe one complete old or new generation; no
  sequence of per-source renames is exposed to them.
- Raw paths, Git, editors, build tools, and readers that do not use the lock
  do not get that atomic-visibility guarantee.
- A fully authenticated candidate can remain after a rejected pre-pivot apply.
  Bounded staging and retained-generation residue is inventory, not a selected
  commit.
- Failure after the `ACTIVE` replacement is an explicit `SPX-I212` ambiguity;
  the implementation does not silently roll back a possibly selected new
  generation.
- Garbage collection, rollback policy, flat materialization, repository
  migration, and power-loss recovery remain future protocols.
- Existing single-file Patch/A0/Impact/Review/Repair/Target/Evidence protocols
  are unchanged. Workspace v1 embeds admitted patches per file but grants those
  artifacts no new authority.

## Rejected alternatives

### Sequential per-file replacement

Rejected because portable readers can observe a mixture of old and new files.
Recovery also cannot infer a unique committed set from an interrupted rename
sequence without another publication record.

### Filesystem-specific directory exchange

Rejected as the public contract because portable Rust and the supported host
matrix do not expose one identical no-replace/exchange primitive with the
required semantics. It would also overstate network and hostile-filesystem
behavior.

### Git commit as transaction authority

Rejected because Git state is not the compiler's authenticated live source
authority, ordinary working trees can be dirty, and editor/raw-file readers
would still observe path-by-path materialization.

### Database or opaque package as canonical source

Rejected for this tranche because readable `.spx` remains the canonical Git
projection. The managed tree is an opt-in publication layer, not a replacement
language storage format.

### Widen single-file A0

Rejected because it would conflate two trust boundaries and risk changing the
frozen single-file protocol. Workspace v1 has its own permanent lock,
generation inventory, and `ACTIVE` publication authority.
