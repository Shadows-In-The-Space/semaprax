# Graph-operational execution evidence v2

Status: reviewed local runner passed all 9 selected rows at exact subject
`4e6751f92525ed8e4bb5e859233616df7adc86d1`; bundle
[`e3a9378c33342571621026f9a8c98a191e06e8521faeb97c223a3a0e74801a7f`](evidence/graph-operational/4e6751f92525ed8e4bb5e859233616df7adc86d1/e3a9378c33342571621026f9a8c98a191e06e8521faeb97c223a3a0e74801a7f/evidence.json).

Audience: release engineers, compiler contributors, and programme reviewers.

V2 extends [v1](GRAPH-OPERATIONAL-EXECUTION-EVIDENCE-V1.md). Neither version's
result transfers to a later commit. The runner remains:

```sh
python3 scripts/graph-operational-evidence.py
```

Run it against a clean, exact local commit. It runs three locked, offline Cargo
integration binaries one at a time. A qualifying envelope uses
`semaprax.graph-operational-execution-evidence.v2` and includes three Cargo logs
and both task-economics reports: SHA-1 and SHA-256.

## Closed selected inventory

| Gate | Selected passing rows |
| --- | ---: |
| `graph_operational_git_workflow_v1` | 4 |
| `candidate_managed_publication_v1` | 4 |
| `graph_operational_managed_workflow_v1` | 1 |

The Git gate retains both twelve-step object-format workflows and the real
stale-ref displacement case. Its fourth row delegates a real local Git
compare-and-swap, injects loss of the successful provider result, and requires
terminal `publication_uncertain` behavior with no retry. The managed-publication
gate checks read-only preparation, exclusive-lock ordering, hostile proof and
host binding, raw-source drift, exact immutable-generation bytes, and unchanged
raw source. The integrated managed workflow joins signature evolution, sibling
merge, impact/diff review, interpreter tests, separate managed publication, and
stale-base rejection.

Every selected row must run and pass; none may be ignored. The runner rejects
extra rows, missing reports, dirty input or output state, subject drift,
malformed summaries, and mismatched artifact inventories or digests.
`Cargo.toml` and `Cargo.lock` are bound repository inputs. The output is private
derived evidence. It is neither source nor permission to publish.

The reviewed Darwin arm64 invocation used Cargo/Rust 1.98.0, Git 2.47.1 and
Python 3.14.2. Its five artifacts and envelope replay under the v2 bundle
domain. This is local evidence for the named subject, not for this later archive
commit or a hosted platform.

## Boundaries

A passing v2 bundle may claim only the selected local workflows on its recorded
host. It does not prove a physical crash, power loss, remote-repository result
loss, durability, deployment, native or Wasm runtime execution, hosted or
cross-platform behavior, full quality, a release tag, general ownership-sensitive
signature evolution, comparative productivity, or programme completion.
