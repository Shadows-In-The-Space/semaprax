# Workspace Execution Migration v1

Status: **HOSTED GREEN** for the bounded v0.4.0 injected-handler implementation.

Audience: compiler, Project, ProgramRoot, semantic-service, runtime, and
durable-checkpoint maintainers.

The [v0.4.0 release baseline](RELEASE-0.4.0-STATUS.md) supersedes the former
local-only and hosted-pending evidence classification.

This profile combines [Workspace Execution Association v1](WORKSPACE-EXECUTION-ASSOCIATION-V1.md)
and [Agent State Migration v3](AGENT-STATE-MIGRATION-V3.md) to bind a checked
migration between two workspace generations. Existing state-migration and
durable-runtime contracts stay unchanged.

## Migration preparation

Preparation consumes the matching old-workspace producer, its actual durable
`Suspend` evidence, and the destination-workspace producer. It retains both
generations and checks the old suspend's provenance and the destination
selection before calling the existing pure migration operation. Caller-supplied
state, roots, tasks, or proposals cannot replace a producer or its evidence.

The resulting public association uses
`semaprax.workspace-migration-association.v1` and commits the old and
destination workspace-binding digests, the two plain runtime-association
digests, and the migration-root digest. It contains no private State, task, or
proposal bytes. A separate `semaprax.workspace-migration-evidence.v1` receipt
is produced only by an actual migration run and binds the actual evidence
root; preparation alone never mints execution evidence.

## Resume and execution

Resume validates the caller's trusted checkpoint and independently trusted
expected handoff through the existing recovery API. It reconstructs the
public migration association from freshly retained compiler state, then
exact-compares the canonical receipt bytes and digest. It does not deserialize
an arbitrary receipt or treat receipt data as authority.

A fresh migration can use the consuming `run` or `run_durable` path; a recovered
migration is durable-only. `run_current` and `run_durable_current` check the
destination binding before any destination stage, checkpoint-store write, or
injected host operation. They reject a stale destination. Ordinary run paths
allow historical bindings, and the previous generation remains a valid
historical association.

Durable failures keep their existing details, including uncertain intent.
Uncertain work is not retried automatically. The caller still owns trusted
checkpoint-store authority. `into_evidence` keeps the producer's existing
transfer semantics and creates no second association.

An actual migrated durable `Suspend` may feed a subsequent migration, so a
chain A to B to C retains the existing cumulative call, byte, fuel, iteration,
stage, and handoff accounting. Each link independently verifies its
predecessor provenance; current-run paths also check destination currentness.

## Boundaries

The profile owns no disk store and adds no service wire, MCP, CLI, or snapshot
structure. It does not claim a durable semantic service, automatic
reconciliation, cross-store exactly-once handoff, or a broader migration
association. Existing workspace roots, runtime associations, state-migration
handoff/checkpoint bytes, and rich failure values retain their prior meaning.

Focused evidence uses:

```sh
cargo test --locked -p semaprax --test agent_runtime_v1 execution_revision -- --nocapture
```

The three workspace migration cases in the original fifteen-test execution
selection exercise A→B→C with recovered B suspension,
zero host redispatch on replay, cumulative nine-call completion, independently
reminted receipt and mismatched predecessor rejection, stale destination
refusal before host or store,
and terminal lost acknowledgement with the selected completion preserved.
The selector also includes the earlier direct runtime, workspace binding,
and durable migration regressions and later linked-role additions. The
implemented release corpus is **HOSTED GREEN**; the original local test count
is a historical corpus description, not a ceiling on current evidence.
