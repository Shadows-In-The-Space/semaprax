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

- **Two `[dependencies]` edges on bundled standard-library packages**:
  `std.auth = "=0.1.0"` (session lifecycle, password-hash policy bounds) and
  `std.jobs = "=0.1.0"` (claim/lease/retry/idempotency state machines). Both
  packages existed under `std/` before this change but were not yet wired
  into the compiler's closed bundled-dependency registry
  (`src/project/standard_dependencies.rs`), so no ordinary project could
  declare them; this change adds `std.auth`, `std.db`, `std.http`, and
  `std.jobs` to that registry (see the accompanying Rust regression in the
  same file). Only `std.auth`/`std.jobs` are used here -- see the ceiling
  below for why.
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
  runs the entry and conformance closures on the interpreter, on native C11
  at `-O0`/`-O2`, and on Core Wasm under Node -- the same shape
  `agent_response_project.rs`/`vector_stats_project.rs` already assert for
  their own sibling reference projects.

## Non-claims

- No password is hashed and no signature is verified: `std.auth` is a pure
  policy/state-machine layer with no hashing or signing host capability (see
  `docs/AUTHENTICATION-SESSIONS-V1.md`'s own non-claims). A real deployment
  performs both outside this decision.
- No socket, database, or job queue is opened. `run_scenario` is a fixture
  walk over caller-supplied ticks and byte literals, not a running server.
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
`builder_bytes` pre-bound) is charged against the whole link closure -- own
source plus every dependency actually reached -- exactly as
`examples/agent-response-project/README.md` already documents for a single
dependency. Composing all four candidate packages (`std.auth` 17,208 B +
`std.jobs` 8,983 B + `std.http` 5,746 B + `std.db` 4,739 B = 36,676 B of
dependency source, transitively pulling in `std.bytes` too) with roughly ten
distinct functions used across them exceeded the bound outright, even with
this project's own source under 12 KB and even after consolidating from six
of this project's own modules down to three. Dropping to two dependencies
(`std.auth` + `std.jobs`, 26,191 B combined) with nine distinct functions
admits cleanly. The breakpoint tracks the **combined reached closure**, not
raw dependency byte count alone: a first, minimal probe using all four
packages but only one function from each (four total) also admitted, so the
number of *distinct functions pulled from each package* -- not merely which
packages are named in `[dependencies]` -- drives the charge. This is
consistent with `agent-response-project`'s own measurement that "adding a
second dependency ... costs far more than it saves," and is further evidence
for issue #241.

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
`std.jobs` closure.

What still refuses on the checked-in project is this project's **own**
source. `src/core.spx` owns `task_service.core.identifier_byte_ok` and is
therefore the source the rename rewrites, and it carries 29 comment lines.
A rewritten source's comments would be dropped by the canonical formatter, so
refusing is correct -- and, unlike the old whole-workspace scope, it is
fixable here. Authoring `src/core.spx` comment-free would complete issue
\#194 step 7's apply/retest half; the comments are kept deliberately because
this file is reference documentation as much as it is code, so the write side
of that demonstration stays open by choice rather than by construction.

**Neither `std.log` nor `std.tracing` can be added to this project's
dependency closure.** Both packages are wired into the compiler's bundled
dependency registry, and both were tried against a scratch copy of this
project's manifest in this session. `std.tracing` is the lighter of the two
candidates -- `std.encoding` is its only transitive dependency, versus
`std.log`'s four (`std.data.json.utf8`, `std.data.json.write`, `std.io`,
`std.log.redact`) -- and it is refused too: `semaprax check` reports
`SPX-G171`'s static admission pre-charge already reaching 19,160,008 bytes
against the 18,874,368-byte cap (**101.5%**) from `std.auth` + `std.bytes` +
`std.encoding` + `std.jobs` + `std.tracing` alone, in canonical path order --
before this project's own three source files are resolved at all. Adding
`std.log` instead is refused the same way, and by a wider margin before its
full five-package closure is even completely counted: the pre-charge already
reaches 19,080,680 bytes (**101.1%**) from only the first five
alphabetically-ordered dependency modules, before `std.jobs`, `std.log`, or
`std.log.redact` are reached. Adding both together reaches 19,922,880 bytes
(**105.6%**). Because this pre-charge sums whole reachable *modules*
regardless of which functions this project's own source calls (the same
"whole-file, not whole-project" charge shape this README's `std.auth`/
`std.jobs` measurement above already documents), no reduction of this
project's own three files can close the gap -- the checked-in baseline
(`std.auth` + `std.jobs` + `std.bytes`) alone already sits at roughly 92.7%
of the cap by the estimate above, and at 88.2% (16,656,400 bytes) measured
freshly in this session via the real build's own fallback-mode accounting
(`checked_retention_prebound_with_uncached_peak`, the same ladder
`semaprax check` actually walks); either way, the remaining headroom is
under 12%, and even the lighter candidate's whole-file charge exceeds it
outright.
`tests/useful_data/task_service_project.rs::adding_std_tracing_to_the_dependency_closure_exceeds_the_builder_bytes_cap`
pins this as a regression: it patches a scratch copy of this project to add
`std.tracing` and one trivial probe function, and asserts `semaprax check`
refuses with `SPX-G171`. This is the same `SPX-G171` ceiling named above and
in issue #241, not a new one.

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
