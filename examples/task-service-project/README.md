# Task service project

A small multi-user task-tracking service composed entirely from bundled
standard-library decision layers: register, log in, create/update a domain
record, enqueue and complete a background job, query its status, log out,
and reject an unauthorized or invalid request. Every step is deterministic
fixture mode -- no socket, no file, and no real clock are touched.

```sh
semaprax check examples/task-service-project
semaprax test  examples/task-service-project
semaprax run   examples/task-service-project
```

## What it demonstrates

- **Three `[dependencies]` edges on bundled standard-library packages**:
  `std.auth = "=0.1.0"` (session lifecycle and password-policy bounds),
  `std.jobs = "=0.1.0"` (claim/lease/retry/idempotency state machines), and
  `std.tracing = "=0.1.0"` (pure W3C trace-context shape and caller-classified
  secret policy). The first two packages became project-selectable when
  `std.auth`, `std.db`, `std.http`, and `std.jobs` joined the compiler's
  closed bundled-dependency registry; `std.tracing` was already selectable.
  The tracing dependency contributes no telemetry emission authority.
- **Row-level authorization**, not just session validity:
  `task_service.core.task_owner_authorized` requires both a usable session
  *and* that the session's own account matches the row's owner. A retired
  (logged-out) session and a different account are both refused.
- **Idempotent job enqueue**: a retried request carrying the same
  idempotency key is a harmless duplicate (`std.jobs.idempotency`'s outcome
  `1`), never a second job.
- **The full acceptance scenario and both rejection paths** are exercised
  twice: once end to end in `task_service.core.run_scenario` (driven by
  `task_service.app.main`), and once as four independent, narrower
  assertions in `task_service.tests` (success path, unauthorized access,
  invalid input, duplicate enqueue).
- **Three execution lanes, not only the interpreter**:
  `tests/useful_data/task_service_project.rs::entry_and_conformance_return_zero_on_interpreter_native_and_wasm`
  runs entry and conformance on the interpreter and native C11 at `-O0`/`-O2`;
  Core Wasm under Node runs the conformance closure only -- the same shape
  `agent_response_project.rs`/`vector_stats_project.rs` already assert for
  their own sibling reference projects.

## Non-claims

- No password is hashed and no signature is verified: `std.auth` is a pure
  policy/state-machine layer with no hashing or signing host capability (see
  `docs/AUTHENTICATION-SESSIONS-V1.md`'s own non-claims). A real deployment
  performs both outside this decision.
- No socket, database, or job queue is opened. `run_scenario` is a fixture
  walk over caller-supplied ticks and byte literals, not a running server.
- No log or span is emitted, exported, or collected. `std.tracing` only
  checks a caller-supplied trace ID, parent ID, flags, and whether the caller
  has classified the event as secret; an adapter must perform classification
  and any eventual emission outside this pure decision.
- The domain record and job are modeled as plain scalar facts (an id, an
  owner account id, a status), not an authored `record`, because
  `Public Useful Data Export v1` -- the `[exports].web` gate every
  `semaprax.manifest.v1` project must satisfy -- admits no authored aggregate
  anywhere in a project that also declares a web export (`SPX-W121`).
- The identifier and HTTP-method grammars are small local reimplementations
  of `std.db.identifier.is_valid` and `std.http.method_is_valid`, not those
  packages themselves -- see the ceiling below.

## Limits this example is shaped by

**`SPX-G171`** (the workspace semantic graph's 18,874,368-byte
`builder_bytes` pre-bound) is charged against the reached link closure -- own
source plus the selected dependency declarations -- exactly as
`examples/agent-response-project/README.md` documents. Before issue #124's
reachability pruning, composing the four candidate domain packages
(`std.auth`, `std.jobs`, `std.http`, and `std.db`) with roughly ten distinct
functions exceeded the bound even after this project was consolidated from
six modules to three. The current three-dependency closure instead selects
only the declarations reached from `std.auth`, `std.jobs`, and `std.tracing`
(including `std.bytes`, `std.encoding`, and `std.log.redact`) and admits
cleanly. Adding real `std.http` and `std.db` behavior remains outside this
fixture and must be measured against that same reached-closure bound rather
than inferred from raw source byte counts.

Separately, the built-in persistent semantic cache (`semaprax
semantic-cache-persist`/`-load`, `docs/PERSISTENT-SEMANTIC-CACHE-V1.md`) could
**not** be exercised on this project at all: even the two-dependency
(`std.auth` + `std.jobs`) configuration exceeds `SPX-G256`'s separate,
smaller 16,777,216-byte (`MAX_PROJECT_CHECKED_MODULE_CACHE_PREBOUND` in
`src/project/incremental.rs`) checked-module-cache construction pre-bound,
even though the same project fits under `SPX-G171`'s larger 18 MB workspace
graph bound for plain `check`/`test`/`run`. This is new evidence for issue
#241: the persistent-cache path has a tighter ceiling than plain checking,
so a project that compiles today may still be unable to use the semantic
cache. See this repository's fast-restart measurement (in the issue #194
worker report) for the exact reproduction and the calculator-project numbers
measured in its place.

**A third, independent ceiling blocks the write side of a semantic rename on
this project.** `tests/useful_data/task_service_project.rs::stable_id_rename_inspect_and_context_succeed_preview_pins_the_comment_precondition`
walks issue #194 step 7's inspect/context/impact/preview chain against
`task_service.core.identifier_byte_ok`: `available_operations` (inspect),
`semantic_context`, and `semantic_impact` all succeed exactly as designed.
`preview` -- validating a `rename_display_name` transaction -- fails closed
with `SPX-G525` -- but no longer for the reason first recorded here.

Universal Semantic Transaction v1 used to require the *entire* workspace to
be comment-free canonical, and that workspace included every bundled
dependency source actually reached, not only this project's own three
modules. `std.auth` carries 253 `//` comment lines and `std.jobs` 34, and
bundled dependency source is compiler-immutable, so no project declaring a
`[dependencies]` edge on a commented bundled package could ever satisfy the
precondition by editing its own source.

Issue #274 fixed that at the structural cause. `ProjectCandidate::apply`'s
`materialize` step now preserves an untouched program's exact base bytes
instead of re-deriving every source through the comment-dropping canonical
formatter, and `src/project/semantic_transaction/canonical_sources.rs`
requires comment-free canonical source only of the sources a transaction
actually rewrites. Checked directly: with this project's own three modules
copied out and stripped of comments, `semaprax change preview <copy>
rename-display-name task_service.core.identifier_byte_ok
identifier_char_is_safe` succeeds against the same commented `std.auth` +
`std.jobs` + `std.tracing` closure.

What still refuses on the checked-in project is this project's **own**
source. `src/core.spx` owns `task_service.core.identifier_byte_ok` and is
therefore the source the rename rewrites, and it carries 31 comment lines.
A rewritten source's comments would be dropped by the canonical formatter, so
refusing is correct -- and, unlike the old whole-workspace scope, it is
fixable here. Authoring `src/core.spx` comment-free would complete issue
\#194 step 7's apply/retest half; the comments are kept deliberately because
this file is reference documentation as much as it is code, so the write side
of that demonstration stays open by choice rather than by construction.

**`std.tracing` now fits, but only as a pure policy dependency.** Its reached
closure includes `std.encoding` and `std.log.redact`; the checked-in
`trace_context_is_admitted` call validates W3C-shaped IDs and refuses a
caller-classified secret. `tests/useful_data/task_service_project.rs` pins
that real closure and runs the application’s tests on the interpreter, native
C11, and Core Wasm; the entry runs on the interpreter and native C11 only.
This is not `std.log`, an emission
adapter, span export, or a claim that any observability profile is supported.
`std.log` remains deliberately absent and is not represented as a supported
fallback by this reference application.

**This project's manifest does not qualify for `semaprax build --target
oci`.** [OCI Deployable Artifact v1](OCI-DEPLOYABLE-ARTIFACT-V1.md) is
implemented only for a Project manifest carrying the frozen
`semaprax.project.v1` schema under the `ScalarV1` profile. This project uses
`schema = "semaprax.manifest.v1"` (the extensible Useful Data Export v1
table-format manifest, required by its `[dependencies]`/`[exports]` sections)
under the `useful-data.v1` profile -- a different schema and profile
entirely. Running `semaprax build --target oci examples/task-service-project`
refuses closed with `SPX-J142` ("the oci target requires the Project v1
scalar profile; no other profile is wired to OCI packaging"), exactly as
documented. Qualifying would mean rewriting this project onto the older
flat `semaprax.project.v1` schema, which has no `[dependencies]` table and
therefore cannot express this project's `std.auth`/`std.jobs` composition at
all -- the two are mutually exclusive today, not a gap in this project's
authoring.
