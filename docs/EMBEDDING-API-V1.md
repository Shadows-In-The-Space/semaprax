# Embedding API v1

Status: versioned bounded reference; the completion matrix owns product
status. First real slice of issue #203's compiler-embedding surface.

Audience: host authors (editors, build systems, services, applications)
embedding SEMAPRAX analysis in-process, and compiler contributors extending
`src/embedding_api.rs`.

## Read this first: two modules both cite issue #203, for different reasons

`src/semantic_embedding/` (documented in
[Semantic Embedding v1](SEMANTIC-EMBEDDING-V1.md)) and `src/embedding_api.rs`
(this document) both carry `#203` in their history, and that is a genuine
naming collision worth stating plainly rather than leaving implicit:

- **`semantic_embedding`** computes a **vector embedding** (bytes → `Vec<f32>`
  via an injected model provider) — the machine-learning sense of the word.
  Its own document says outright: "Issue #203 asks for a much larger
  surface... None of that lives in this module." It is a real, tested,
  capability-gated boundary, but it answers only issue #203's "explicit
  provider/capability injection" bullet, applied to one narrow sub-case the
  issue never actually names (a vector-embedding effect). It does not touch
  compiler/session creation, source/Project load, check, or any of issue
  #203's other seven "in scope" bullets.
- **`embedding_api`** (this module) is the **compiler-embedding** sense of
  the word issue #203's title and body actually describe: "editors, build
  systems, services, and applications embed parsing, checking,
  interpretation, semantic query, candidate validation, and selected
  execution without spawning the CLI or receiving ambient host authority."

Concretely: a host wanting the vector-embedding boundary imports
`semaprax::semantic_embedding`; a host wanting to check SEMAPRAX source
in-process imports `semaprax::embedding_api`. Neither module re-exports or
depends on the other.

## What issue #203 asks for, and where each part actually stands on `main`

Issue #203's "In scope" list, mapped to real code, as of this tranche:

| In-scope bullet | Status before this tranche | Status after this tranche |
| --- | --- | --- |
| Compiler/session creation | Not exposed as a small stable API. `src/project/semantic_service.rs`'s `SemanticWorkspaceService::open` exists but requires an already-built `Arc<ProjectRevision>`. | [`open_project_session(input)`](../src/embedding_api/project_session.rs) opens an opaque, caller-owned in-memory Project session. Compiler revisions, cache, service, and candidates remain private. |
| Source/Project load and authenticated refresh | `SemanticWorkspaceService`/`ProjectSnapshot` do this for a full Project (multi-file, manifest-driven). No embedding-facing Project input existed. | [`ProjectSessionInput`](../src/embedding_api/project_session.rs) accepts only owned manifest/source bytes; [`ProjectSession::refresh`](../src/embedding_api/project_session.rs) delegates exact stale checking and staged adoption to the existing service. It never opens a source label as a host path. |
| Check | `crate::check` (crate root) and the CLI `check` command both exist, but neither is documented as a stable embedding surface, and `crate::check` silently discards non-error diagnostics on a successful check. | `check_source` is that documented surface for one unit, and deliberately keeps every diagnostic (warnings included) on success — see "Diagnostics are never discarded on success" below. |
| Format, graph/query/context | `format::canonical`, `graph::to_json`, `graph::context_json`, `graph::agent_context_json`, and `graph::agent_context_v2_json` already exist as public functions. | [`format_source(unit_name, source)`](../src/embedding_api.rs) re-exposes canonical formatting; [`graph_source(unit_name, source)`](../src/embedding_api.rs) re-exposes `graph::to_json`; [`context_source(unit_name, source, symbol, options)`](../src/embedding_api.rs) wraps bounded forward v1 context; and [`context_v2_source(unit_name, source, symbol, options)`](../src/embedding_api.rs) wraps bounded forward, reverse, or bidirectional v2 context through facade-owned options. Each has the same panic-normalization and no-ambient-authority guarantees. The legacy unbounded-depth `graph::context_json` remains outside this facade. |
| Candidate validate/replay | `src/project/candidate/**` implements this for the Project workspace transaction path. | [`ProjectSession::validate_candidate_v2`](../src/embedding_api/project_session.rs) and [`ProjectSession::replay_candidate_v2`](../src/embedding_api/project_session.rs) return canonical authority-free reports over the active generation. |
| Deterministic interpreter execution for admitted profiles | `interpreter`/`hosted_interpreter` exist. | [`execute_entry_source(capability, unit_name, source, options, cancellation)`](../src/embedding_api/execution.rs) executes only the existing prepared, zero-argument `i64` entrypoint profile. It requires [`ExecutionCapability`](../src/embedding_api/execution.rs), caller bounds, and a cooperative cancellation token; no source-native host effect receives a provider or ambient fallback. |
| Explicit provider/capability injection | Done, for the vector-embedding effect only, by `semantic_embedding::EmbeddingCapability`/`EmbeddingProvider` (see above). | `check_source` needs no capability because checking is pure and effect-free; this bullet is satisfied for *this* operation by construction (nothing to inject authority into), not by adding an unnecessary capability type. |
| Memory/resource ownership and cancellation | Not documented for any embedding surface. | Stateless analysis calls hold no resource across calls. A `ProjectSession` owns only in-memory compiler cache/service state and normal Rust drop releases it. [`EmbeddingCancellation`](../src/embedding_api.rs) pre-cancels Project opening/refresh and samples bounded context before work and before returning a successful report; it does not promise an unsafe mid-refresh interruption. [`ExecutionCancellation`](../src/embedding_api/execution.rs) cooperatively cancels the bounded interpreter call. |
| Version/feature negotiation | Not present for any embedding surface. | [`EMBEDDING_API_VERSION`](../src/embedding_api.rs), `EmbeddingApiVersion::is_compatible_with`, `require_compatible`, and `negotiate_features` check major/minimum minor and exact operation/profile names. Unknown features fail closed with `SPX-EMB004`. |
| Thread-safety and reentrancy contract | Not documented. | `check_source` takes no shared or mutable state. `ProjectSession` makes no `Sync`, clone, reentrancy, or simultaneous-refresh promise; refresh/candidate validation take `&mut self`. A caught stateful-operation panic poisons the handle, requiring callers to drop and reopen it from explicit bytes. |

## The `CheckOutcome` contract

[`CheckOutcome`](../src/embedding_api.rs) is the only value `check_source`
returns. It carries `unit_name` (echoed back, never read from disk),
`ok: bool`, `diagnostics: Vec<Diagnostic>`, and `revision: Option<String>`
(present exactly when `ok` is `true`). It deliberately never carries
[`crate::ast::Program`], [`crate::hir::Analysis`], or
[`crate::hir::ResolvedProgram`] — issue #203's "Validated internals remain
compiler-owned" acceptance criterion applied literally: an embedder gets a
report, never a value whose internal shape this crate is free to change
release to release.

### Diagnostics are never discarded on success

The crate-root [`crate::check`] helper (used throughout this repository's own
tests) returns `Ok(Program)` on success and, in doing so, throws away every
non-error diagnostic — a real embedder using that helper directly would
never see a warning on a program that still checks. `check_source` calls
[`crate::hir::analyze`] directly instead (the same function the CLI `check`
command uses) and keeps `diagnostics` in full regardless of `ok`.
`a_declaration_missing_id_still_checks_ok_but_keeps_its_warning` in
`src/embedding_api.rs`'s test module locks this in against the missing-`@id`
`SPX-S103` warning specifically.

### No ambient authority

`check_source` opens no file, spawns no process, and reaches no network.
`unit_name` labels diagnostics only; it is never opened as a path.
`unit_name_is_never_read_from_disk` proves this concretely: checking valid
source under a `unit_name` that names a path guaranteed not to exist on the
running machine still succeeds, because the function's only real input is
`source`.

### Panic normalization

A parser or analyzer defect must not unwind across this boundary into a
host's own stack. `check_source` runs the actual analysis inside
`std::panic::catch_unwind` and converts a caught panic into a
[`Diagnostic`] carrying [`PANIC_NORMALIZED_DIAGNOSTIC_CODE`]
(`"SPX-EMB001"`) — a code reserved for exactly this case and never produced
by parsing or analyzing real source. Because manufacturing an actual
parser/analyzer panic on demand would not be an honest regression fixture,
the panic path is proven with a private test-only `SourceChecker`
implementation that panics on purpose
(`embedding_boundary_normalizes_a_panic_into_a_diagnostic_never_propagating_
the_unwind`), the same seam-substitution pattern
`src/semantic_embedding/fixture.rs`'s `ScriptedEmbeddingProvider` already
uses in this repository to prove a path a pure, always-succeeding fixture
cannot reach on its own.

### Distinguishing a genuine refusal from an internal defect

`malformed_source_fails_with_the_specific_parser_diagnostic` checks a module
with no function body (`"module app.empty;\n"`), which the parser refuses
with `SPX-P101` ("a module must declare at least one function") before any
HIR analysis runs, and asserts that diagnostic's code and message never
mention `PANIC_NORMALIZED_DIAGNOSTIC_CODE`. The panic-normalization test
asserts the reverse: its diagnostic never mentions `SPX-P101`. A caller can
therefore always tell "your source is invalid" (`SPX-P101` or any other real
diagnostic code) apart from "the compiler itself broke while checking your
source" (`SPX-EMB001`) — two refusal paths that a less careful test could
conflate.

## The `FormatOutcome` contract

[`FormatOutcome`](../src/embedding_api.rs) is `format_source`'s only return
value, deliberately shaped like `CheckOutcome`: `unit_name` (echoed, never
read from disk), `ok: bool`, `diagnostics: Vec<Diagnostic>`, and
`canonical_source: Option<String>` (present exactly when `ok` is `true`).
Unlike `check_source`, a successful format does not require semantic (HIR)
validity — only a successful parse — because `crate::format::canonical`
renders the parsed AST directly and never calls `crate::hir::analyze`.
`a_declaration_missing_id_still_formats_ok` locks this in: a program missing
`@id` (a `check_source` warning) still formats with no diagnostics at all.
`format_source` shares `check_source`'s exact no-ambient-authority
guarantee (`format_unit_name_is_never_read_from_disk`) and panic
normalization (`embedding_format_boundary_normalizes_a_panic_into_a_
diagnostic_never_propagating_the_unwind`, proven the same way — a
private test-only `SourceFormatter` double that panics on purpose, since a
real formatter defect cannot be manufactured honestly). A malformed unit
fails with the same specific parser diagnostic `check_source` would produce
(`malformed_source_fails_format_with_the_specific_parser_diagnostic`), never
conflated with `PANIC_NORMALIZED_DIAGNOSTIC_CODE`.
`valid_source_formats_to_its_own_canonical_projection` additionally proves
idempotency: reformatting an already-canonical unit reproduces
byte-identical output.

## The `GraphOutcome` contract

[`GraphOutcome`](../src/embedding_api.rs) is `graph_source`'s only return
value, shaped like `CheckOutcome`/`FormatOutcome`: `unit_name` (echoed,
never read from disk), `ok: bool`, `diagnostics: Vec<Diagnostic>`, and
`graph_json: Option<String>` (present exactly when `ok` is `true`).
`graph_source` is a thin forwarding wrapper over the already-public
`crate::graph::to_json`, not a reimplementation:
`valid_source_graph_matches_graph_to_json_exactly` asserts its output is
byte-identical to calling `graph::to_json` directly on the same parsed
program, so a stub or a divergent reimplementation would fail that
assertion. It shares `check_source`'s no-ambient-authority guarantee
(`graph_unit_name_is_never_read_from_disk`) and panic normalization
(`embedding_graph_boundary_normalizes_a_panic_into_a_diagnostic_never_
propagating_the_unwind`, proven the same way — a private test-only
`SourceGrapher` double that panics on purpose). A malformed unit fails with
the same specific parser diagnostic `check_source`/`format_source` would
produce (`malformed_source_fails_graph_with_the_specific_parser_
diagnostic`), never conflated with `PANIC_NORMALIZED_DIAGNOSTIC_CODE`.

**One deliberate, tested difference from `check_source`:** a successful
`graph_source` call's `diagnostics` is always empty, even when the checked
program has a real warning (e.g. a missing `@id`). `graph::to_json` resolves
through `hir::resolve`, whose own success path
(`resolved.ok_or(diagnostics)`) drops the diagnostics it collected along the
way; `graph_source` forwards to that function rather than reimplementing
resolution to recover them.
`a_declaration_missing_id_still_graphs_ok_but_the_warning_is_not_carried_
forward` locks this in on both sides at once: it asserts `check_source`
*does* keep the `SPX-S103` warning on the same source, then asserts
`graph_source` does not — so the two facts stay pinned together, and a
future change to either function's discard behavior fails a test that names
exactly which contract broke. A host that wants both the rendered graph and
every warning must call `check_source` and `graph_source` separately on the
same `source`.

## The `ContextOutcome` contract

[`context_source`](../src/embedding_api.rs) exposes the deterministic,
byte- and node-bounded forward v1 semantic-context query for a caller-supplied
unit and function display name or persistent declaration ID. Its
[`ContextOptions`](../src/embedding_api.rs) is a closed embedding-facing
surface: `depth`, `max_bytes`, `max_nodes`, and only the v1-compatible
contracts, ownership, effects, and types facets. `ContextOptions::new` calls
the canonical graph option validator, preserving its limits and `SPX-G004`
diagnostics for malformed bounds, duplicate filters, or no filters; it does
not create another validation vocabulary.

[`ContextOutcome`](../src/embedding_api.rs) echoes `unit_name` and `symbol`,
returns canonical `semaprax.agent-context.v1` JSON on a match, and keeps
compiler-owned AST, HIR, and graph query state private. A resolved query with
no matching function is a normal success (`ok: true`, `context_json: None`).
As with `graph_source`, successful context rendering does not preserve
non-error analysis warnings, so hosts that need warnings call `check_source`
on the same bytes. The wrapper forwards byte-for-byte to
`graph::agent_context_json`; its focused tests lock direct parity, no-match,
canonical option rejection, parser failure, pathless input, and panic
normalization (`SPX-EMB001`).

[`context_v2_source`](../src/embedding_api.rs) uses the same closed outcome
and exact source/bound handling with [`ContextV2Options`](../src/embedding_api.rs).
It adds only a closed [`ContextDirection`](../src/embedding_api.rs): forward,
reverse, or both. The wrapper forwards to `graph::agent_context_v2_json`, and
the focused tests pin byte-for-byte bidirectional parity, a successful
no-match, and separate panic normalization. It does not expose graph-owned v2
option types or traversal state.

## Compatibility policy

`EMBEDDING_API_VERSION` (currently `1.7.0`; `1.1.0` after `format_source`,
`1.2.0` after `graph_source`, `1.3.0` after `context_source`, and `1.4.0`
after `context_v2_source`, then `1.5.0` after `execute_entry_source`, and
`1.6.0` after the Project session facade, and `1.7.0` after explicit
version-refusal and pre-cancelled request entry points) names
this Rust surface's own version,
independent of any checked SEMAPRAX program's semantics.
`EmbeddingApiVersion::is_compatible_with(requested_major)` returns `true`
only when `requested_major` equals this build's `major`; `require_compatible`
turns a mismatch into the stable `SPX-EMB002` diagnostic rather than silently
assuming compatibility. `EmbeddingCancellation` reports `SPX-EMB003` only
when it was observed before a request starts, or (for pure context) before its
successful report is returned; it never claims the graph/project kernels were
interrupted mid-operation.
`version_negotiation_accepts_matching_major_and_refuses_a_different_one`
tests both a match (`1`) and two refusals (`0` and `2`). Within one major
version, each existing function's accepted inputs and each existing outcome
and options type's fields are additive-only: a future `1.x` may add a field
to an outcome type or a new function alongside them, but will not remove or
repurpose an existing field, and will not change any existing function's
signature. A breaking change to any of those requires bumping `major` and updating
`EMBEDDING_API_VERSION` in the same change. Adding `graph_source` and then
`context_source`, `context_v2_source`, and `execute_entry_source` are additive
`1.x` changes: each
adds a new function and closed outcome/options type without changing an
existing type or function's shape.

## What this tranche deliberately does not do

Naming every nonclaim explicitly, per this repository's honesty-bar
convention:

- **No ambient source provider.** `ProjectSessionInput` owns manifest and
  source bytes. Its source labels are inventory labels only; the facade accepts
  no filesystem, environment, network, or callback provider. Full Project
  admission remains in `src/project/**` and occurs before a session opens or a
  refresh adopts.
- **No general execution or host-effect provider.** `execute_entry_source`
  admits only the existing deterministic, zero-argument `i64` entrypoint
  profile. It does not execute arbitrary functions, Project test closures,
  generated targets, source-native host effects, filesystem, process, or
  network operations. No provider object is accepted because no effectful
  operation is admitted by this slice.
- **No C ABI.** Issue #203 explicitly sequences a C ABI after "stable owned
  string/record/result conventions are selected" for the Rust surface. This
  tranche is that Rust surface's first slice, not the ABI.
- **No publication from a candidate report.** Candidate JSON/evidence returned
  by the session is authority-free. The facade provides no commit, publication,
  Git, filesystem, or generated-artifact authority.
- **No legacy depth-only context facade.** `context_source` and
  `context_v2_source` expose the bounded graph contracts with closed options.
  They do not expose the older `graph::context_json` route, whose output and
  depth-only option contract need their own compatibility decision.

## Evidence

Local, offline unit tests (`cargo test --locked -p semaprax --lib
embedding_api`): a valid program checks with no diagnostics and a
revision; a program missing `@id` still checks `ok` while keeping its
`SPX-S103` warning; a module with no function fails specifically with
`SPX-P101`; a `unit_name` naming a nonexistent path still succeeds because
only `source` is read; a deliberately panicking test double is normalized to
`SPX-EMB001` rather than unwinding; and version negotiation accepts a
matching major version while refusing two different ones — plus, for
`ProjectSession`: caller-owned calculator manifest/source bytes open an
in-memory service, stale and invalid refreshes retain the old workspace
revision, malformed query/candidate bytes return closed diagnostics, and a
valid canonical query plus v2 transaction replay to identical candidate and
result reports — plus, for
`format_source`: a valid program formats to its own canonical projection and
reformatting that output is idempotent; a program missing `@id` still
formats `ok` (formatting needs no HIR validity); a module with no function
fails formatting with the same `SPX-P101`; a `unit_name` naming a
nonexistent path still succeeds; and a deliberately panicking test double is
normalized to `SPX-EMB001` rather than unwinding — plus, for `graph_source`
(this tranche): a valid program's graph is byte-identical to calling
`graph::to_json` directly on the same parsed program; a module with no
function fails with the same `SPX-P101`; a `unit_name` naming a nonexistent
path still succeeds; a deliberately panicking test double is normalized to
`SPX-EMB001` rather than unwinding; and a program missing `@id` still
renders `ok` with an empty `diagnostics` (proven alongside `check_source`
keeping that same warning on the same source, pinning the documented
contrast between the two functions). No test in this module spawns a
process, opens a network socket, or reads a real file from disk.

The graph-only tranche previously recorded `cargo test --locked -p semaprax
--lib embedding_api::tests` → **16 passed, 0 failed** (11 pre-existing + 5
for `graph_source`). The context addition extends that focused module with
direct parity, no-match, canonical-option-refusal, malformed-source,
pathless-input, and panic-normalization cases. The v2 addition adds
bidirectional direct parity, no-match, and panic-normalization cases; exact
results belong to the current change's verification record rather than that
historical count.

### Standalone host consumer

[The standalone Rust consumer](../examples/embedding-api/README.md) imports
only `semaprax::embedding_api` and exercises successful checking, exact
canonical formatting and idempotence, graph identity, malformed-source
diagnostics, retained warnings, and API-major rejection. Run it with
`cargo run --locked --offline --manifest-path examples/embedding-api/Cargo.toml`.
It has its own Cargo workspace and lockfile. Its dependency is a local path
to the compiler checkout; this is local consumer evidence, not validation
of an installed or published registry package.

### Exact feature negotiation and cancellation

`negotiate_features(major, minimum_minor, required_names)` validates against
`SUPPORTED_FEATURES`, with at most 32 names of at most 128 bytes each. A differing
major or unsupported minimum minor returns `SPX-EMB002`; an unknown name or
capacity violation returns `SPX-EMB004`. The returned read-only `EmbeddingFeatures`
is availability information. Execution still requires `ExecutionCapability`.
There is no implicit profile fallback or authority in this result.

Both `context_source_with_cancellation` and
`context_v2_source_with_cancellation` sample the monotonic host signal before
analysis and before returning a successful report. Project open and refresh
sample only before starting; cancellation never reports an uncommitted state
after the persistent service has adopted a generation. A pre-cancelled refresh
leaves its handle usable and its old revision intact.
