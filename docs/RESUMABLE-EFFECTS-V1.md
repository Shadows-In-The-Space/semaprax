# Resumable effects v1

Status: **reference validator**, not yet source syntax. Issue #204 asks the
compiler to let an ordinary, non-Agent function declare typed resumable
effects with the same generality Aver's `yield` lowering has. This slice
delivers a Rust-level generic driver and journal (`src/resumable_effects/`)
proving the suspend/resume semantics, plus this design. It adds no `.spx`
syntax, HIR node, verifier rule, graph projection, or backend lowering --
see [Scope boundary](#scope-boundary).

Audience: compiler contributors implementing the source-syntax/HIR/backend
generalization this document specifies, and reviewers auditing what #204
delivered versus what remains.

## What already exists on `main`

Before this change, three things already ship, HOSTED GREEN, for exactly one
closed shape:

- `agent_lifecycle::iterative::compile_agent_lifecycle_v2`
  ([Agent iterative lifecycle v2](AGENT-ITERATIVE-LIFECYCLE-V2.md)) lowers
  one AgentDefinition's fixed six-role
  `initialize`/`observe`/`propose`/`authorize`/`execute`/`reduce` operations
  into a `Continue`/`Complete`/`Suspend`/`Fail` `Step` state machine.
- `agent_lifecycle::iterative::effects::compile_typed_effects`
  ([Agent typed effects v3](AGENT-TYPED-EFFECTS-V3.md)) binds a bounded,
  ≤64-row operation registry of typed host effects to that same state
  machine, checked against a deployment's allowed tool/effect IDs.
- `agent_runtime_v2::checkpoint`
  ([Agent operation checkpoint v2](AGENT-OPERATION-CHECKPOINT-V2.md))
  durably journals each turn as `Intent`/`Observed`/`Transition` entries and
  proves replay against a trusted store dispatches zero new host calls for
  an already-completed run.

All three are real, tested, and **outside this module's lease** — nothing in
`src/resumable_effects/` edits them. What none of them do, and what #204
requires, is expose this shape to an arbitrary function: every type in the
existing stack is the AgentDefinition's `task`/`state`/`observation`/
`proposal`/`outcome`/`result` roles, decoded from one closed
`semaprax.agent-definition.v1` JSON document. There is still no general
"a function declares a typed effect, the compiler lowers it" mechanism on
`main`. `rg -l "suspend|resumable|yield" src/` before this change confirms
this: every hit is either this closed Agent stack, an unrelated iterator/
for-loop `yield`-shaped identifier, or `live_invocation`'s single
`model.invoke` boundary (`docs/LIVE-INVOCATION-CONTRACT-V1.md`), which is
itself only a generalization of *one* effect, not of suspend/resume itself.

## Design: the general shape

A resumable computation over caller-chosen `State`, `Result`, `Request`,
`Observation`, `CleanupOp` types is:

```text
request:    State -> Option<Request>                       // is this turn a suspension point?
transition: (State, Option<&Observation>) -> Step<State, Result>
cleanup_plan: State -> Vec<CleanupOp>                       // canonical order, terminal-only
```

`Step` is the existing `Continue`/`Suspend`/`Complete`/`Fail` vocabulary,
unchanged in shape from the Agent profile. `transition` is the one place all
of a program's semantics live, and it is called *identically* whether its
`observation` was just physically dispatched or replayed from a trusted
journal entry — that identity of call is what makes replay a re-*use* of
trusted recorded observations rather than a second, possibly divergent,
re-*execution* (see [What matters](#what-matters-and-how-it-is-tested)
below). This is the same principle
`agent_runtime_v2::checkpoint`'s recovery already documents ("recovery
re-executes deterministic stages under new persisted fuel reservations...
compares every retained transition against the newly checked reducer
result"), generalized from one Agent reducer to an arbitrary `transition`.

A journal entry additionally carries an `EffectScope { program_root,
invocation_id, policy_epoch }`, generalizing
`live_invocation::identity::LiveInvocationSeed` from one effect
(`model.invoke`) to an arbitrary program. `Journal::validate` rejects any
entry whose scope disagrees with a caller-supplied *expected* scope — the
caller re-derives that scope independently every time, exactly as
`LiveInvocationSeed` is re-derived rather than read back off a journal — so
a copied or replayed journal can never become a bearer credential for a
different program root, invocation, or policy epoch (the "reminted resume"
failure case #204 names explicitly).

## What this reference module implements

`src/resumable_effects/core.rs`:

- `ResumableEffectProgram`: the trait above. `State`, `Result`, `Request`,
  `Observation`, `CleanupOp` are each bound `Clone + Eq + Debug + 'static`.
- `Step<S, R>`: `Continue | Suspend | Complete | Fail(i64)`.
- `EffectHandler<Req, Obs>` / `CleanupHandler<Op>`: the only injected
  physical boundaries. Nothing in the driver itself opens a file, spawns a
  process, contacts a network, or otherwise acquires ambient authority
  merely by running a suspend/resume program — the driver's own settlement
  of a `Step` is proof data about what the program decided, never a grant to
  act on it.
- `Journal<P>` / `JournalEntry<P>`: an append-only, canonical-order record
  of `Intent`/`Observed`/`ObservationFailed`/`Transition` entries.
  `Journal::validate` rejects a journal before it is trusted for replay:
  `StaleProgramRoot`, `WrongInvocation`, `WrongPolicyEpoch` (three distinct
  scope-field mismatches, not one merged variant), `OutOfOrder`,
  `RequestMismatch`, `NonSequentialTurn`, `EntryAfterTerminal`, and
  `UnterminatedIntent` (a journal ending on a bare `Intent` is uncertain —
  whether the physical dispatch happened is unknown — and is rejected
  before any stage, mirroring `agent_runtime_v2::checkpoint`'s identical
  rule).
- `run` / `resume`: the driver. `resume` replays every entry the journal
  already has — recomputing `request`/`transition` and asserting they
  agree with the recorded entries (`RequestDrift`/`TransitionDrift` if not)
  — without ever calling the injected handler for a replayed turn, then
  performs genuinely new turns past the journal's recorded tail as fresh
  dispatches with their own accounting. Both functions return the journal
  on *every* path, including failure, so a caller keeps the latest durable
  checkpoint candidate even when a call fails (mirroring
  `DurableTypedFailure`).
- Cleanup only runs for `Complete`/`Fail` (a `Suspend` deliberately keeps a
  computation's resources live for a later resume); cleanup ops run in
  exact `cleanup_plan` order, exactly once, and a cleanup failure is
  recorded in `Outcome::cleanup` but never replaces the already-selected
  `terminal` — failure selection is sticky by construction, not by a
  downstream check.

`src/resumable_effects/capability.rs`:

- `CapabilityPolicy`: a bounded (≤64, mirroring
  `AGENT-TYPED-EFFECTS-V3.md`'s own registry ceiling), ordered, duplicate-
  and empty-id-rejecting allowlist of capability ids.
- `CapabilityGatedHandler`: wraps an already-injected `EffectHandler` and
  refuses, before the wrapped handler is ever called, any request whose
  caller-supplied `capability_of` mapping names an id outside the current
  policy. A denial is reported through the driver's existing
  `HandlerFailed`/`ObservationFailed` path — the same one a genuine host
  failure already takes — so it is durable journal evidence, not a silently
  dropped decision, and replaying a denied journal reports the same denial
  again without a second call to the wrapped handler (or the gate itself).
  This implements the "Effect declarations and capability requirements"
  scope bullet as a decorator at the existing effect-authority boundary,
  rather than a change to `run`/`resume` or the `ResumableEffectProgram`
  trait.

`src/resumable_effects/migration.rs`:

- `StateMigration<From, To>` / `migrate_suspended`: a pure state-migration
  function between two `ResumableEffectProgram`s' `State` types, evaluated
  *twice* and rejected on disagreement, mirroring the exact pattern
  `execution_revision::typed_migration` and `live_invocation::migration`
  already prove for real checked state types ("evaluate a pure migration
  function twice, reject disagreement, carry cumulative budget forward").
  Only a genuinely `Suspend`ed outcome is a migration candidate; migrating
  under an unchanged `program_root` is refused (`resume`'s journal-replay
  path is correct there, not migration). A successful migration carries the
  old revision's cumulative `Outcome::dispatched` count forward in
  `MigratedState` rather than silently resetting it. This function mints no
  effect authority and performs no dispatch itself — its result is a new
  `State` a caller must still drive through the ordinary `run`/`resume`
  machinery under a freshly derived scope. This implements implementation-
  sequence step 7 ("Implement pure state migration functions between
  compatible ProgramRoot revisions and reject incompatible state changes")
  at the reference level; it does not yet migrate a real checked state type
  produced by source-syntax lowering, because no such lowering exists yet
  (see [Scope boundary](#scope-boundary)).

`src/resumable_effects/signature.rs`:

- `EffectSignatureTable`: a bounded (≤64, the same ceiling), ordered,
  duplicate- and empty-rejecting table of `EffectSignature { effect_id,
  request_shape, answer_shape }`. `answer_shape` is the "what resuming this
  suspension must supply" half of a typed resumable effect — the half
  `core`'s whole-program `Observation` type parameter cannot express.
- **Why it is needed.** `ResumableEffectProgram` fixes exactly one
  `Request`/`Observation` pair per program, so `rustc` rejects an
  observation of the wrong *Rust* type. That is a whole-program channel
  type, not a per-effect one. A computation that waits on several distinct
  effects must model `Request`/`Observation` as enums or tagged records, and
  at that point Rust sees one type and checks nothing about *which* effect a
  given answer answers: a `clock` suspension can be resumed with a `model`
  answer, and both the handler boundary and a recovered journal accept it
  silently. This module is that missing check, and only that check.
- `SignatureCheckedHandler`: a decorator over an already-injected
  `EffectHandler`, in the same shape as `CapabilityGatedHandler` and
  composable with it in either order. It refuses an undeclared effect id or
  a request whose shape disagrees with its declaration *before* the wrapped
  handler — the only physical effect boundary — is called at all, and
  refuses an answer that names a different effect, or the right effect in
  the wrong shape, before that answer can become the observation a
  `transition` reads. Both refusals travel the driver's existing
  `HandlerFailed`/`ObservationFailed` path, so `run`/`resume` are unchanged,
  the refusal is durable journal evidence, and it can never replace an
  already-selected terminal status. The answer check necessarily runs after
  the wrapped handler returns — an answer cannot be inspected before it
  exists — so a genuinely authorized physical effect may already have
  happened when an answer is refused; what the refusal guarantees is that a
  mismatched answer never becomes an `Observed` entry or reaches a
  `transition`.
- `validate_journal_signatures`: the same check re-applied to a *recovered*
  journal. `Journal::validate` checks scope, ordering and request identity,
  but it compares an `Observed` entry's observation against nothing —
  observation and request are the program's own two Rust types and any pair
  of them is structurally legal. A hand-tampered or corrupted checkpoint can
  therefore pass `Journal::validate` and still be refused here, reported as
  the exact entry index plus a distinct `SignatureMismatch` variant
  (`UnknownEffect`, `RequestShapeMismatch`, `AnswerForWrongEffect`,
  `AnswerShapeMismatch`). Journal order is preserved: the first offending
  entry is reported, and the journal is never sorted, skipped past, or
  repaired.
- **Nothing here runs anything.** Constructing a table, checking a shape and
  validating a journal are pure functions over caller-supplied data: they
  dispatch no effect, spawn no work, and mint no authority. A signature is
  proof data about what an answer must look like, never permission for
  anything to produce one. Shapes are caller-supplied opaque strings
  compared for exact equality, not nominal HIR type identities; deriving a
  shape string from a real checked source type is owned by the
  syntax/HIR tranche in [Scope boundary](#scope-boundary), which this
  checking discipline is deliberately independent of so that it is testable
  now.

## What matters, and how it is tested

- **Replay is not re-execution.** `resume_from_a_truncated_journal_only_dispatches_the_new_tail`
  proves a 3-turn run resumed from a 1-turn-recorded prefix dispatches
  exactly the 2 remaining turns, never the first. `replay_of_a_completed_run_makes_zero_new_effect_dispatches`
  and `replay_of_a_suspended_run_reproduces_the_same_suspension_with_zero_dispatch`
  wire a handler that **panics** if called, so a stray dispatch fails loudly
  rather than silently passing. `replaying_a_recorded_failed_dispatch_never_recontacts_the_host`
  proves the same holds for a recorded *failure*: replay reports the same
  deterministic failure again rather than re-attempting the call.
- **A settlement is proof data, not permission.** The driver never holds a
  file handle, socket, or process; `EffectHandler`/`CleanupHandler` are the
  only injection points, matching every other effect boundary in this
  codebase (`live_invocation::model_invoke::ModelHandler`,
  `agent_lifecycle`'s `TypedEffectHandler`).
- **Failure selection is sticky.** `cleanup_failure_never_overrides_the_already_selected_terminal_status`
  runs both a `Fail` and a `Complete` case, each with one cleanup entry
  engineered to fail, and asserts the terminal status is unchanged in both
  — plus a negative-control `assert_ne!` against the other status in each
  case, so the two paths cannot be silently confused with each other.
- **Cleanup-plan vectors are canonical runtime order.** `cleanup_plan`
  returns a fixed `Vec`; the driver iterates it front-to-back and every
  cleanup-asserting test checks the exact recorded order, not just
  membership.
- **Typed effects are a compile-time diagnostic, not a runtime surprise.**
  `ResumableEffectProgram` fixes one `Request`/`Observation` pair per
  program (a monomorphic type parameter, not a boxed/erased channel), so
  presenting an observation of the wrong type is a `rustc` type error. The
  module-level `compile_fail` doctest in `src/resumable_effects.rs` (run by
  `cargo test --doc`) proves this executes as a real compiler rejection,
  not just a documentation claim. A second `compile_fail` doctest proves the
  `'static` bound rejects a borrowed local as a program's `State` — the
  reference validator's compile-time ownership gate.
- **Specific, not merged, diagnostics.** `validate_rejects_a_stale_program_root_specifically`,
  `..._a_wrong_invocation_specifically` and `..._a_wrong_policy_epoch_specifically`
  each assert the exact `JournalError` variant returned **and** assert the
  other two variants are *not* what was returned, so the three scope fields
  cannot be silently conflated into one underspecified rejection.
- **Corruption and reminted-resume refusal are caught before any dispatch.**
  `resume_rejects_a_replayed_request_that_disagrees_with_recomputation` and
  `..._a_replayed_transition_that_disagrees_with_recomputation` hand-tamper
  a completed journal's recorded request/transition (in a way that still
  passes `Journal::validate`'s structural check, so the drift is caught only
  by the driver's own recomputation) and assert `RequestDrift`/
  `TransitionDrift`, with a panicking handler proving zero new dispatches
  happened first. `resume_refuses_a_journal_presented_under_a_different_invocation_scope`
  proves a genuine, valid, completed journal cannot simply be replayed under
  a different scope — the journal itself carries no authority to be
  resumed; only a caller-supplied, independently-derived matching scope
  does.
- **Owned locals transfer intact across suspension.**
  `owned_state_transfers_intact_across_a_suspension` carries a growing,
  non-`Copy` `Vec<String>` log through two suspensions and asserts its exact
  contents in the `Suspend` carrier.
- **A resume that does not match is refused, twice over.**
  `an_undeclared_effect_is_refused_before_the_wrapped_handler_is_called` and
  `a_request_whose_shape_disagrees_with_its_declaration_is_refused_before_the_wrapped_handler`
  wire a wrapped handler whose `dispatch` **panics** if called at all, so
  "refused before the effect boundary" is proven rather than asserted.
  `an_answer_naming_a_different_effect_never_becomes_an_observation` offers a
  perfectly well-formed `model` answer against a pending `clock` suspension —
  a swap `rustc` cannot see, because both are the same Rust type — and
  asserts the run fails and the journal contains **no** `Observed` entry.
  `a_tampered_answer_that_structural_validation_accepts_is_refused_by_signature_checking`
  asserts `Journal::validate` returns `Ok` for the tampered journal and
  `validate_journal_signatures` still refuses it at the exact entry index,
  so the new check demonstrably catches something the existing structural
  validator cannot.
  `a_journal_recovered_under_a_table_that_no_longer_declares_its_effect_is_refused`
  is the "resuming after a code change can execute state under incompatible
  semantics" case. `a_refused_answer_is_replayed_as_the_same_refusal_without_a_second_dispatch`
  proves the refusal is exactly-once: the replay wires a panicking handler.


## Scope boundary

Explicitly **not** done in this slice, and why:

- **No `.spx` syntax, HIR node, verifier rule, or graph projection.** The
  repository's change protocol requires parser, canonical formatter,
  resolver/HIR, verifier, semantic graph, native backend and Wasm backend to
  move together once syntax carries runtime meaning. That is a
  multi-subsystem change; landing a half-wired parser rule with no checked
  HIR consumer, or an HIR node no backend lowers, would violate that
  protocol rather than satisfy it. This document is the design that
  follow-up work implements against — the same relationship
  `LIVE-INVOCATION-CONTRACT-V1.md` already has to the HIR-integration issues
  it exists to unblock (#109–#116, #178–#181 per that document).
- **Shapes are opaque caller-supplied strings, not checked source types.**
  `EffectSignature`'s `request_shape`/`answer_shape` are compared for exact
  equality. Deriving such a shape from a real checked source type — so that
  the *compiler* computes what a suspension waits for rather than the caller
  declaring it — belongs to the syntax/HIR tranche below. What exists here
  is the checking discipline and its refusals, not a source-derived type
  identity.
- **No compiler-checked ownership analysis.** `'static + Clone + Eq + Debug`
  is this reference module's own approximation of "plain owned, transferable
  data" — it rejects a borrow or a non-`'static` handle the same way a real
  ownership checker would reject an escaping reference, but it is not the
  compiler's alias/uniqueness analysis over real HIR locals. Wiring a real
  `yield` point to the existing ownership/ cleanup-plan machinery
  (`cleanup_plan::build`) so the compiler itself computes which locals cross
  a suspension is follow-up work this design enables but does not perform.
- **State migration exists only at the reference level.**
  `src/resumable_effects/migration.rs`'s `migrate_suspended` now proves the
  checked-migration *pattern* (`execution_revision::typed_migration` and
  `live_invocation::migration`'s "evaluate twice, reject disagreement,
  carry cumulative budget forward") for an arbitrary caller-chosen `State`
  pair. It does not migrate a real checked state type produced by
  compiler-owned source-syntax lowering, because no such lowering exists
  yet; that is still downstream of the syntax/HIR tranche below, and this
  module intentionally does not add a second, competing migration story
  once that lowering lands.
- **No native/Wasm lowering, no Agent-runtime migration onto this
  mechanism.** Both are named in #204's implementation sequence as steps 8
  and "interpreter first, then native/Wasm" — downstream of the
  syntax/HIR/verifier tranche above, not reachable without it.
- **No checkpoint byte-wire format.** `Journal`/`JournalEntry` are in-memory
  Rust values in this slice; `Journal::from_entries` is the seam a future
  canonical-JSON or byte-wire codec (matching
  `agent_runtime_v2::checkpoint`'s compact-JSON, sorted-key, bounded wire)
  would decode into, but no such codec exists yet here.

## Acceptance criteria: met here versus open

| Criterion (from issue #204) | Status |
| --- | --- |
| A non-Agent function can yield typed requests and resume safely | **Reference-validator level only.** `ResumableEffectProgram` is a Rust trait any non-Agent Rust type can implement and drive; no `.spx` source can do this yet. "Typed" is now per-effect, not only per-program: `EffectSignatureTable` declares what each effect's request looks like and what resuming it must supply, and a resume that does not match is refused (`SignatureCheckedHandler` before the effect boundary, `validate_journal_signatures` on a recovered journal). |
| Generated state machines are deterministic semantic projections | Proven at the reference level: `transition` is required to be a pure function and drift from that requirement is caught (`RequestDrift`/`TransitionDrift`). Not yet a compiler-generated projection from source. |
| Ownership, effects, contracts and authority survive suspension correctly | Ownership: reference-level `'static`/`Clone` gate only (see above). Effects: `EffectHandler` is the sole authority boundary; `CapabilityGatedHandler` checks a declared capability id against a bounded allowlist before that boundary is reached, and `SignatureCheckedHandler` independently checks the declared request and answer shapes, refusing an answer that answers a different effect before it can become an observation. Contracts (pre/postconditions) and real compiler-checked ownership: **open**, need HIR integration. |
| Checkpoint/recovery never grants effect authority by itself | **Met**, including at the "reminted resume" level: `Journal`/`resume` never dispatch on a replayed entry, and a valid journal is refused outright under a scope the caller did not itself derive. |
| Agents can progressively reuse the mechanism rather than remain a separate runtime island | **Open.** `agent_lifecycle`/`agent_runtime_v2` are untouched (outside this module's lease); migrating even one Agent fixture onto `resumable_effects` is follow-up work once the syntax/HIR tranche exists for it to lower into. |

## Gate

`cargo test --locked -p semaprax --lib resumable_effects::` (46 unit tests:
30 for `core`/`capability`/`migration`, 16 for `signature`) and
`cargo test --locked -p semaprax --doc resumable_effects` (2 `compile_fail`
doctests proving the typed-resume and ownership compile-time rejections) are
this module's focused selectors. All of it is local, offline, re-runnable
evidence; nothing hosted, native, or Wasm is claimed.
