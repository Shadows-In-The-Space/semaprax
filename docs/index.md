# SEMAPRAX documentation

Status: public alpha documentation map.
Audience: language users and integrators. SEMAPRAX is alpha.

Start with a guide below. Use the [reference catalog](#reference-catalog) when
you need an exact syntax, wire-format, or ABI contract. Contributors should
start with [First contribution](FIRST-CONTRIBUTION.md).

The [v0.4.0 baseline](RELEASE-0.4.0-STATUS.md) is the last release with a
**HOSTED GREEN** implementation claim. At this document's 2026-09-24 update,
the [v0.6.0 tag gate](https://github.com/wavect/semaprax/actions/runs/36047757697)
was still in progress; v0.6.0 was not published or signed. The last
downloadable archives were the
[v0.5.0 prerelease](https://github.com/wavect/semaprax/releases/tag/v0.5.0)
for Linux x86-64, Apple Silicon macOS, and Windows x86-64. Read the
[completion matrix](COMPLETION-MATRIX.md) before treating a versioned contract
as a supported feature: a specification is not proof of implementation.

## Choose a path

| You want to… | Start here |
| --- | --- |
| Install and run your first program | [Install](INSTALL.md) → [Quickstart](QUICKSTART.md) |
| Learn the language | [Language tour](LANGUAGE-TOUR.md) → [RFC 0001](RFC-0001.md) |
| Find a command or example | [CLI guide](CLI-GUIDE.md) · [Examples](https://github.com/wavect/semaprax/blob/main/examples/README.md) |
| Fix a diagnostic | Run `semaprax help diagnostic <SPX-code>`; list codes with `semaprax help diagnostic codes` |
| Find a library API | [Standard-library catalog](STANDARD-LIBRARY-CATALOG.md) |
| Build a multi-file project | [Project Manifest v1](PROJECT-MANIFEST-V1.md) |
| Write `.spx` as an agent | [Agent quick reference](AGENT-QUICK-REFERENCE.md) |
| Query or change program meaning | [Agent Context v2](AGENT-CONTEXT-V2.md) → [Semantic Patch v2](SEMANTIC-PATCH-V2.md) |
| Contribute to the compiler | [First contribution](FIRST-CONTRIBUTION.md) → [Development guide](DEVELOPMENT.md) |
| Check feature or release status | [Completion matrix](COMPLETION-MATRIX.md) · [Release status](RELEASE-0.6.0-STATUS.md) |

## Core concepts

### Source and identity

Keep readable `.spx` files in Git. Public declarations can have stable `@id`
values, so tools can recognize them across edits. Expression IDs may change
with each revision. The formatter gives equivalent source one canonical form.

### Checked semantic representation

The compiler checks source before it produces HIR (its checked intermediate
form) and a versioned semantic graph. Agents can ask that graph focused
questions instead of reading an entire project.

### Evidence and authority

Reports and evidence describe what was checked; they do not grant permission
to write. A change must still authenticate its inputs, replay its evidence,
and use an authorized transaction.

### Shared backend meaning

Native and WebAssembly backends use the same checked HIR and cleanup plan.
Evidence applies only to the targets and program shapes named by each
feature's specification.

## Public language and workflow references

- [RFC 0001](RFC-0001.md) is the full language and toolchain contract.
- [RFC 0002](RFC-0002-ALGEBRAIC-DATA.md) covers records, variants, and
  ownership; [RFC 0003](RFC-0003-CLEANUP-AND-RESOURCE-ABI.md) covers cleanup.
- [Project Manifest v1](PROJECT-MANIFEST-V1.md) defines multi-file projects.
  Later manifests add specialized profiles, including
  [Useful Data](PROJECT-MANIFEST-V16.md),
  [Process I/O](PROJECT-MANIFEST-V18.md), and
  [checked filesystem outcomes](PROJECT-MANIFEST-V19.md).
- [Wasm Scalar Exports v1](WASM-SCALAR-EXPORTS-V1.md) defines the selected
  JavaScript/TypeScript scalar boundary.
- The [owned-byte](PUBLIC-OWNED-DATA-API-V1.md),
  [flat-record](PUBLIC-FLAT-OWNED-RECORD-API-V1.md), and
  [owned-string](PUBLIC-OWNED-UTF8-API-V1.md) APIs have hosted release
  regression evidence but remain unpublished and unpromoted. Check each
  contract and the [completion matrix](COMPLETION-MATRIX.md) before using one.

## Agent workflow references

Agent tools follow this sequence:

```text
graph/context → patch → impact/review → evidence replay → atomic apply
```

Validation checks a proposed change; it does not apply it.

- [Agent Context v2](AGENT-CONTEXT-V2.md) explains focused graph queries.
- [Semantic Patch v2](SEMANTIC-PATCH-V2.md) defines single-file changes;
  [Impact](SEMANTIC-IMPACT-V1.md) and [Review](SEMANTIC-REVIEW-V1.md) preview
  their effects without writing.
- [Iterative lifecycle v2](AGENT-ITERATIVE-LIFECYCLE-V2.md) and
  [Direct Runtime v2](AGENT-RUNTIME-V2.md) cover bounded source Agent runs.
- [Project Agent Transport v5](PROJECT-AGENT-TRANSPORT-V5.md) defines an
  opt-in, read-only transport. Hosted regression evidence does not mean public
  promotion.
- [Diagnostic Repair v1](DIAGNOSTIC-REPAIR-V1.md) covers repair discovery;
  [Patch Evidence v2](SEMANTIC-PATCH-EVIDENCE-V2.md) covers replayable proof.
  The [catalog](SUMMARY.md) lists earlier versions and specialized protocols.

## Reference catalog

Versioned reference documents are intentionally precise. They define one wire
format, report, ABI, admission profile, or evidence boundary. They are useful
to tool and host authors but are not the recommended introduction to SEMAPRAX.

The exhaustive, audience-separated list is in the [reference catalog](SUMMARY.md):

- public language and workflow references;
- agent and workspace protocol references;
- target, ABI, schema, and package projections;
- internal architecture, quality, status, roadmap, decisions, and private
  experiment contracts.

## Compatibility and status

- [v0.4.0 baseline](RELEASE-0.4.0-STATUS.md) owns the current hosted-green release
  evidence classification and its relationship to historical evidence.
- [Protocol migrations](MIGRATIONS.md) records compatibility changes between
  versioned agent-facing formats.
- [Completion matrix](COMPLETION-MATRIX.md) owns product status and completion
  criteria.
- [Changelog](https://github.com/wavect/semaprax/blob/main/CHANGELOG.md) owns historical implementation changes.
- [Changelog summary](CHANGELOG-SUMMARY.md) gives a compact latest-notes view.
- [Roadmap](ROADMAP.md) owns future sequencing, not implementation claims.

Keeping these responsibilities separate prevents the same status narrative
from drifting across the README, RFCs, architecture, and roadmap.
