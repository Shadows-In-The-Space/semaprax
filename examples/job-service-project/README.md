# Job service project

A small durable-jobs reference service composed from the bundled `std.jobs`
standard-library decision layer, plus one real, checked `.spx` job handler
that the host `JobRuntime` actually calls to execute a durable job -- not
only a fixture walk over scalar facts. Issue #192's audit found the durable
job runtime itself (lease/expiry/heartbeat/crash recovery,
retry/backoff/dead-letter ceilings, payload/handler revision migration,
concurrent-enqueue idempotency, database transaction integration) genuinely
complete, with real tests in `src/job_fixture.rs`, `src/job_runtime.rs`, and
`src/job_evidence.rs`; the gap was a reference service that could actually
enqueue and execute a durable typed job. This project, together with
`tests/useful_data/job_service_project.rs`, is that reference service.

```sh
semaprax check examples/job-service-project
semaprax test  examples/job-service-project
semaprax run   examples/job-service-project
```

## What it demonstrates

- **A `[dependencies]` edge on the bundled `std.jobs` standard-library
  package** (`std.jobs = "=0.1.0"`), used by `job_service.core` for the pure
  claim/idempotency/retry/dead-letter decision layer
  `job_service.core.run_scenario` walks in deterministic fixture mode --
  register a fresh enqueue as legal, recognize a retried enqueue with the
  same idempotency key as a harmless duplicate, refuse the same key reused
  for different work as a conflict, and retry a failing job once within its
  ceiling before dead-lettering it -- exercised through
  `job_service.tests.scenario_succeeds`, the same shape
  `examples/task-service-project` already demonstrates for
  `std.auth`/`std.jobs` together.
- **A real, checked job handler that the host runtime actually executes.**
  `job_service.app.handle_report_job` is an ordinary explicit-`@id`,
  single-argument, `i64`-returning `.spx` function taking one authored
  `ReportJob` record, declared directly in the entry module (see "Where the
  handler lives" below for why). `tests/useful_data/job_service_project.rs`
  binds this exact function -- compiled from this project's own retained
  source, not a Rust stand-in -- to the host `JobRuntime` through
  `SourceJobHandlerBinding` / `drive_checked_source_job`
  (`src/job_runtime/source_handler.rs`), enqueues a real job, and drives it
  to completion by calling the compiled handler through the existing
  retained-call interpreter seam. `JobRuntime` still owns every checkpoint,
  lease, retry, backoff, and dead-letter transition; the `.spx` handler owns
  only the effect-free classification of one already-admitted payload (see
  "Non-claims" below).
- **An authored record type, because this profile is not Useful Data Export
  v1.** `ReportJob` (the job payload) and `ExportPayload` (the web export's
  return type) are both authored `record`s. `nested-owned-record-api.v1` is
  the profile that exists to admit authored records in a project with a web
  export -- `Public Useful Data Export v1`'s `SPX-W121` refusal ("does not
  admit authored aggregates or resources") is specific to the scalar-only
  profile family (`useful-data.v1`/`v2`, the family
  `task-service-project` and `agent-response-project` use), not to this one.
- **Three execution lanes for the `.spx` fixture walk, not only the
  interpreter**:
  `tests/useful_data/job_service_project.rs::entry_and_conformance_return_zero_on_interpreter_native_and_wasm`
  runs the entry and conformance closures on the interpreter, on native C11
  at `-O0`/`-O2`, and on Core Wasm under Node -- the same shape
  `task_service_project.rs`/`agent_response_project.rs` already assert for
  their own sibling reference projects.
- **Fault injection carried through to the real runtime**, not only the
  `.spx` fixture walk (each performed manually against a compiled binary,
  confirmed red, then reverted -- see the exact reproduction in each named
  test's own doc comment):
  `source_handler_binding_executes_the_real_compiled_handler_to_completion`
  breaks when `handle_report_job` is edited to ignore its payload and always
  return a constant status.
  `source_handler_binding_retries_within_ceiling_then_dead_letters` enqueues
  one job whose real compiled handler always reports a retryable failure,
  drives it through a three-attempt ceiling with the runtime's own bounded
  exponential backoff (`base_backoff_ticks = max_backoff_ticks = 10`, so
  each retry is due exactly 10 ticks after the previous attempt), asserts
  the runtime refuses to claim it again before that tick, and asserts the
  final attempt dead-letters the job rather than retrying it forever; it
  breaks when `max_attempts` is lowered so the ceiling is reached
  immediately instead of after the modeled second attempt.
  `duplicate_idempotency_key_bound_to_this_handlers_identity_is_a_harmless_duplicate`
  ties the same real handler's own deployment identity (not an arbitrary
  byte string) into the durable job store's own dedup/conflict decision, and
  breaks when the retried enqueue's descriptor is changed to a different
  (but still well-formed) identity.

## Where the handler lives, and three previously undocumented constraints this discovered

`job_service.app` (the manifest's `entry` module) declares the payload
record, the checked handler, the web export, and a trivial `fn main() -> i64
{ 0 }` -- all in one file, with **no `use` of any other module** and **no
`//` comment**. Getting there required discovering three independent,
previously undocumented constraints on `SourceJobHandlerBinding`, each
reproduced against the compiled interpreter and pinned by this project's
final shape:

1. **The bound file must be standalone-checkable.**
   `SourceJobHandlerBinding::derive` re-verifies its bound source by calling
   `crate::check(source, path)` on that file's retained bytes alone, with no
   project context. A file with any `use function ... from <module>`
   therefore fails closed with `SPX-G172` ("source module imports require
   Workspace Semantic Graph resolution"), and a file with no `fn main() ->
   i64` fails closed with `SPX-T105` ("executable module must define `fn
   main() -> i64`") -- both mapped to `SourceJobHandlerRefusal::SourceRevisionMismatch`
   by `derive`, which does not otherwise distinguish them. This is why the
   handler cannot live in `job_service.core` (which imports `std.jobs`).
2. **Only the manifest's `entry` module or its `tests` module may declare
   `main` at all.** Every other listed source is what `src/workspace_graph.rs`
   calls a "provider module" and a `main` there fails closed with `SPX-G172`
   ("workspace scalar provider module ... may not declare `main`"), a
   *different* rule from constraint 1, checked at whole-project link time
   rather than at standalone re-verification. Combined with constraint 1,
   the only two files eligible to host a `SourceJobHandlerBinding` target in
   a multi-module project are its `entry` and its single `tests` module (the
   manifest schema admits exactly one `tests` entry), and both must
   otherwise be self-contained.
3. **The bound file must be exactly comment-free.** `crate::graph::revision`
   (what `derive`'s standalone re-check compares against the file's
   originally retained `source_revision`) hashes `format::canonical(program)`
   -- the *parsed* AST re-rendered, which drops `//` comments entirely --
   while the project's own per-file `source_revision`
   (`semantic_workspace::source_revision_with_frontend`) hashes the *raw
   retained source bytes* including comments. For a file with any comment,
   these two hashes disagree, and `derive` reports
   `SourceRevisionMismatch` even though the file parses, checks, and
   round-trips through `semaprax fmt --check` cleanly. This is the same
   family of discovery as `task-service-project`'s own `SPX-G525`
   ("comment-free canonical workspace") finding for Universal Semantic
   Transaction v1, on a different code path: `job_service.app` carries no
   `//` comment anywhere, and this constraint (not house style) is why.

A fourth, related but separate discovery: **the ordinary interpreter's
entry/test execution closure does not admit a call reaching a
record-parameter function at all.** An earlier draft of this project had
`main()` call `handle_report_job` directly with a literal `ReportJob`; on
`semaprax run` this failed with `SPX-F102 (unsupported_callee)` at
`job_service.app.main`'s own body. Calling the checked handler with a real
payload is exactly what `SourceJobHandlerBinding`'s dedicated retained-call
seam exists for instead -- ordinary entry/test execution stays scalar-only,
the same restriction `Public Useful Data Export v1` enforces explicitly for
web exports (see "What it demonstrates" above) but which apparently also
governs plain entry execution independent of any web export at all.

## Non-claims

- **The checked handler performs no I/O.** `job_service.app.handle_report_job`
  takes a payload that already carries a pre-observed outcome classification
  (0 succeeded, 1 transient/retryable, 2 permanent) -- as if decoded from an
  idempotent external call's own response -- and returns it. A real
  deployment's own host code performs that external call and encodes its
  result into the payload before enqueueing; `SourceJobHandlerBinding`'s own
  documentation is explicit that the retained-call route it binds through is
  effect-free by construction (`src/job_runtime/source_handler.rs`'s
  `BoundSourceJobHandler::execute`: "the checked retained-call route is
  effect-free and bounded by interpreter fuel rather than wall/tick time").
  This is not a gap specific to this project: no `.spx` program has ambient
  filesystem, network, or process authority (see `AGENTS.md`'s "Capabilities
  are explicit" invariant), so a checked job handler cannot itself be the
  thing that performs an external call.
- **No checkpoint store, socket, or real clock is opened by `semaprax run`.**
  The project's own `main()` (`job_service.app.main`) is a trivial anchor
  (see "Where the handler lives" above for why); the genuine
  enqueue-and-execute path (a real `JobRuntime`, an in-memory
  `JobCheckpointStore`, and caller-supplied ticks standing in for a real
  clock) is exercised by `tests/useful_data/job_service_project.rs`, which
  is a host test harness, not something reachable from `semaprax run` on
  this manifest. This mirrors `examples/everyday-agent-project`'s own
  non-claim for its durable-agent slice: a job runtime is proof data plus a
  caller's own authority, never a license for compiled code to spawn work or
  open a store on its own.

## Limits this example is shaped by

**`SPX-G171`** (the workspace semantic graph's 18,874,368-byte
`builder_bytes` pre-bound) is charged against the whole link closure -- own
source plus every dependency actually reached. Measured with
`workspace_graph::builder_bytes_report::builder_bytes_breakdown` (added at
`1ae7f819` for `examples/catalog-normalizer-project`) against an earlier,
functionally equivalent four-file layout of this project (the payload,
handler, and export in their own `src/handler.spx` rather than folded into
`src/app.spx` as the final shape above requires), `std.jobs` (six functions
imported), and `std.jobs`'s own transitive `std.bytes` dependency:

| module | own_bytes | total_bytes | imports |
|---|---:|---:|---:|
| `job_service.app` | 42,603 | 93,853 | 1 |
| `job_service.core` | 1,278,308 | 1,550,802 | 6 |
| `job_service.tests` | 608,058 | 844,096 | 5 |
| `std.jobs` | 3,729,416 | 3,777,176 | 1 |
| `std.bytes` | 6,350,722 | 6,350,722 | 0 |

Summed per-module `total_bytes` (the same conservative mode-0 ceiling
`catalog_normalizer_project_reference` reports first) was **12,616,649
bytes** against the 18,874,368-byte cap -- about **33% headroom** even
before any fallback-mode discount -- and `workspace_graph::build_owned` on
that four-file layout's real sources verified outright. The final three-file
layout merges the handler module's declarations into `job_service.app`
(removing one duplicate `module`/import-table charge) and is smaller still;
`semaprax check examples/job-service-project` verifies it end to end, which
is authoritative proof it fits under `SPX-G171` (the CLI's own admission
runs the identical `retention_prebound_mode` charge this instrumentation
replays), even though a byte-exact re-measurement of the final three-file
layout could not be completed in this session -- `cargo test`/`cargo check`
against this repository's own `src/` were unable to compile throughout: four
other lanes were mid-flight on an `ast::ExprKind::Yield` variant rollout
(non-exhaustive `match` errors climbing from 33 to 124 across repeated
attempts in `src/source_verify/`, `src/workspace_graph/expected_projection/`,
`src/hir/`, and elsewhere, none of them files this project touches). This
project uses only one bundled dependency (`std.jobs`) rather than the two
`task-service-project` composes (`std.auth` + `std.jobs`), which is most of
why it fits with room to spare where that sibling project sits at 92.7%: the
combined reached closure, not raw dependency count, drives the charge (see
`task-service-project`'s own README and issue #241).
