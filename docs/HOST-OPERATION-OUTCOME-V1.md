# Host Operation Outcome v1

Status: **implemented with local executable conformance.** The additive
filesystem v3 profile covers interpreter, native C11, and Core Wasm execution.
It does not claim hosted-provider support.

Audience: reviewers deciding whether to admit this profile, the implementing
agent once admitted, and anyone hitting issue #228's gap in the meantime
(directly: issue #123/#124's catalog-normalizer follow-on).

## Why this exists

Issue #228 names an exact hole in the legacy host-operation route.
`file_write_atomic` still aborts the enclosing invocation on provider failure,
while the additive `file_write_atomic_checked` route returns a classified
publication outcome. The checked route is limited to the filesystem family;
network operations remain outside this slice. For the legacy operation:

- `FileFailure` remains the ordinary provider-error `Result` and has no
  `PublishUncertain` variant. The checked provider API instead returns
  `Result<CheckedAtomicWriteOutcome, FileFailure>`, keeping provider errors
  separate from the three valid publication outcomes. The physical provider
  reports `NotPublished` for pre-commit failures, `Uncertain` only for an
  `EIO` from the rename step, and `Published` for a known successful rename.
  See the POSIX rename contract: [The Open Group `rename()`
  specification](https://pubs.opengroup.org/onlinepubs/9799919799/functions/rename.html).
- The checked native lowering uses a separate callback/status path and
  writes the outcome through an out `u64` value. Invalid or unwritten checked
  outcomes fail with status `5`; valid `0`/`1`/`2` outcomes are returned as
  ordinary values. The legacy v2 lowering keeps its existing fail-stop behavior.
- The checked handler now distinguishes *published* (`0`), *not published*
  (`1`), and *uncertain* (`2`) without treating those domain outcomes as
  invocation failure. ABI, capability, malformed-input, and invalid callback
  results still fail closed.

`docs/DURABLE-JOBS-V1.md`'s [checked publication outcome
section](DURABLE-JOBS-V1.md#checked-publication-outcomes-and-recovery-uncertainty)
defines the downstream mapping: the checked provider's actual `UNCERTAIN`
value may feed `std.jobs` outcome kind `3`; ordinary provider failure may not.
This document owns the additive checked operation; the durable host runtime
owns checkpointing, lease recovery, and handler dispatch.

`tests/useful_data/filesystem_v2_native.rs`'s
`filesystem_v2_write_atomic_failure_collapses_into_undifferentiated_abort`
test, added alongside this document, pins the current behavior concretely: a
`write_atomic` provider callback that fails at the point a real "outcome
unknown" failure would occur produces the identical `!semantic_success &&
status_code == 5` shape, and the identical "nothing after it runs" abort, as
an ordinary pre-publication validation failure
(`filesystem_v2_rejects_malformed_list_wire_before_publication`, same file).
Nothing distinguishes them. That legacy regression remains required after the
checked route is lowered; V3 has separate outcome assertions.

## Decision 1: a value-typed outcome, not exceptions or `try`/`catch`

SEMAPRAX has no general exception mechanism and this document does not
propose one. The repository's existing idiom for a closed, checked outcome is
a returned discriminant a caller matches exhaustively — `std.jobs`'s ten
lifecycle codes, the idempotent-enqueue three-way outcome
(`DURABLE-JOBS-V1.md`, "Idempotent enqueue"), and the `provider_outcome`
adapter in `tests/project/standard_library/provider_outcomes.rs` all follow
this shape already, all composed entirely in checked SEMAPRAX with no new
host operation. The gap #228 names is narrower: the legacy host-operation status path cannot
hand back a closed outcome that includes a genuinely uncertain case. The new
checked operation has a value-returning path whose domain-specific outcome
classes do not reach the fail-stop path; malformed input, capability failure,
and ABI/provider-contract defects still do.

## Decision 2: additive, not a breaking change to `file_write_atomic`

`file_write_atomic` keeps its exact v2 signature, status domain, and
abort-on-failure behavior (`docs/FILESYSTEM-IO-V2.md`, frozen). Every program
that already depends on "any failure aborts" keeps that behavior. The
three-way outcome is a **new, separately named operation** admitted under the
additive `filesystem-io.v3` profile (Project v19, graph V46), exactly as issue
#228's acceptance criteria frame it.
This also keeps the first slice honestly scoped to one operation: nothing
here proposes touching `net_send`/`net_recv` or any other family member.
Extending this taxonomy to network operations (the issue's other named
example, and `NetworkFailure::TransferFailed` in
`src/network_provider.rs` is the closest existing analogue — "the peer
reset the connection or a transfer failed midway", exactly a candidate
uncertain case) is explicitly **out of scope for the first slice** and left
as a follow-on once this shape is proven on one operation.

## Scope of the first slice

One operation: `core.host.file-write-atomic-checked`, authored as
`file_write_atomic_checked`, under the additive `FilesystemV3` command profile.
The Project profile is `filesystem-io.v3` (Project v19, graph V46). It
has the same path/data argument shape as `file_write_atomic`, and returns a
closed three-code outcome instead of a byte count. In `std.fs`, the
`write_atomic_checked` wrapper returns the unit variants of `WriteOutcome`
(`Published`, `NotPublished`, and `Uncertain`). Classified publication
outcomes are ordinary values; unrelated ABI or provider-contract defects
still fail closed.

### Closed three-way outcome taxonomy (`HOSTOUT-001`)

| Code | Name | Meaning | Maps from |
| --- | --- | --- | --- |
| `0` | `PUBLISHED` | The atomic replace committed. | `write_atomic_checked` provider success with a known completed rename. |
| `1` | `NOT_PUBLISHED` | The provider can prove the authoritative target was not published. A pre-commit failure may still have created a temporary staging file. | pre-commit validation/provider failures, including invalid path, missing parent, capacity, authority, file type, and other errors for which the provider proves no target publication. |
| `2` | `UNCERTAIN` | The provider began the commit step and cannot confirm whether it completed. | `CheckedAtomicWriteOutcome::Uncertain`, returned only after the provider has started its atomic replace and cannot determine the result (currently rename `EIO`). |

`NotFound` applies when the parent directory is absent: the fixture and
scoped physical providers reject that path before attempting to publish the
target. `HOSTOUT-001` retains its
three codes; widening it (a fourth code, a different code assignment) is a
change to this document, not to the implementation.

The critical admission rule, restated from the repository's own invariant
("failure selection is sticky; cleanup cannot replace the selected status"):
**`UNCERTAIN` is reached only from an externally observed
outcome-unknown signal from the provider itself, exactly the discipline
`std.jobs`'s `UNCERTAIN` state and `std.db`'s `connection_lost` transition
already both hold** (`DURABLE-JOBS-V1.md`, "Checked publication outcomes and recovery uncertainty"). A provider
may not translate every ordinary `IoFailure` into `UNCERTAIN` merely because
uncertainty is a documented case. Nor may it translate every `IoFailure` into
`NOT_PUBLISHED`: the existing physical `write_atomic` maps both temporary
file write failure (before target commit) and `renameat` failure (at the
commit step) to that one variant. The legacy operation retains its fail-stop
behavior; its `Result` is insufficient to implement the new checked outcome
by wrapping or reclassifying it. A checked provider must report the phase
and observed result of its **own** commit attempt. It returns `CheckedAtomicWriteOutcome::Uncertain` only when that attempt was
made and its outcome truly cannot be determined; it reports `NOT_PUBLISHED`
only when it can prove the target was not published. A failure after a confirmed successful rename is
not automatically publication uncertainty; durability and cleanup require
their own precise claims. This phase distinction is a provider-authoring
discipline, and future hostile-input tests must check it rather than infer
it from a legacy error code.

## Capability requirements (`HOSTOUT-002`)

No new ambient authority. `file_write_atomic_checked` requires exactly the
effect `file_write_atomic` already requires (`WRITE_EFFECT`,
`src/filesystem_ops.rs`) — declaring `uses { fs.write }` is necessary and
sufficient, identical to today. This document does not add a "may report
uncertain outcomes" capability distinct from ordinary write authority: the
uncertainty is a property of the *outcome*, not a distinct grant of power, and
adding a second effect for it would let a caller select "abort on I/O
ambiguity" versus "observe I/O ambiguity" per call site, which is exactly the
kind of caller-selectable authority the repository's capability model refuses
elsewhere (a caller cannot opt out of a diagnostic by omitting a capability).

## Diagnostics and admission decisions (`HOSTOUT-003`)

These are the exact diagnostics a lowering must produce; each is stated so a
reviewer or implementer can check a diagnostic string against this table
without re-deriving it.

1. **Undeclared effect.** Calling `file_write_atomic_checked` without `uses {
   fs.write }` produces the existing diagnostic verbatim:
   `"host-command operation requires undeclared effect `fs.write`"`
   (`src/hir/validation/host_command.rs`, `require_effects`). No new
   diagnostic text — this is the same check every host-command operation
   already goes through, extended to one more operation identity.
2. **Non-exhaustive handling.** A caller that does not dispatch on all three
   codes `0`/`1`/`2` (for example, a boolean `== 0` check that silently
   folds `1` and `2` together) is not rejected by this operation's own
   admission rule — `usize` return values are not otherwise constrained by
   exhaustiveness in this language, and inventing an ad hoc exhaustiveness
   check for exactly one operation's return value would be a new admission
   rule with no precedent. Instead, `HOSTOUT-003` requires the **std wrapper**
   exposes (`std.fs.write_atomic_checked`) returns the three-case `WriteOutcome`
   variant. The verifier checks exhaustive `match` handling through its existing
   variant rules. Raw builtin callers may compare or ignore the returned
   `usize`; the raw operation does not impose exhaustive dispatch.

   The source wrapper's `WriteOutcome` is a fieldless, non-generic variant.
   Its cross-module import is admitted through the owned byte-record call lane
   only when the caller directly imports that exact variant type and the
   function's owned record inputs remain otherwise admitted. The result
   carries a Copy case tag; payload variants, resources, generic variants,
   and missing or substituted type imports remain outside this lane. This
   does not widen public Project aggregate exports.
3. **Hostile forgery.** A checked SEMAPRAX caller cannot supply `2` on input
   to *manufacture* an uncertain outcome — the return value is
   compiler-generated from the mapped provider status, never an argument the
   caller controls, so no new input-validation diagnostic is needed on the
   call itself. The hostile-input case this document requires instead is a
   **provider-conformance test**: a reference provider that reports
   `CheckedAtomicWriteOutcome::Uncertain` for a path that was never reached (i.e. before its
   commit step) must be treated as a provider defect to be caught by
   provider test scaffolding, not something the compiler can detect at
   compile time (the compiler has no visibility into the provider's internal
   commit boundary). This document records the requirement; it does not
   attempt to invent a compile-time check for a runtime provider's internal
   honesty, which is outside what a verifier can observe.

## Native, Wasm, and interpreter lowering

The checked operation is wired through the same three execution surfaces while
retaining the legacy v2 route unchanged:

- **Native:** the checked callback and status are separate from the ordinary
  `FileFailure` status. The callback writes an out `u64` outcome; valid
  `CheckedAtomicWriteOutcome` values map to `0`/`1`/`2` and are returned as the
  expression value. Invalid or unwritten callback outcomes fail with status
  `5`; callback/status failures remain fail-closed.
- **Wasm:** the new import is appended as
  `env.spx_filesystem_write_atomic_checked_v3`, with seven `i32` parameters, an
  `i32` status result, and an out `u64` value. The V3 status export is
  `__spx_filesystem_status_v3`. The V2 import and
  `__spx_filesystem_status_v2` export remain unchanged.
- **Interpreter:** `file_write_atomic_checked` maps the provider's
  `Result<CheckedAtomicWriteOutcome, FileFailure>` to an ordinary value, and
  `std.fs.write_atomic_checked` wraps it in the `WriteOutcome` unit variants.

Local conformance executes the three classified outcomes and callback defects
on each backend. The physical Unix provider maps rename `EIO` using its own
commit phase; injected syscall-failure evidence is not claimed.

## Connection to `std.jobs`

A checked SEMAPRAX job handler can now call `file_write_atomic_checked`,
receive `2` (`UNCERTAIN`), and feed that directly as the `kind == 3` input to
`std.jobs.uncertain.retry_next_state_after_outcome` — closing exactly the gap
`DURABLE-JOBS-V1.md`'s checked-publication-outcome section names as the tranche's one
remaining limitation. That wiring is `std.jobs` *composition* work for the
issue that lowers this document, not part of this document's own scope.

## What is and is not covered by this document

**Covered:**
- The decision to add a value-typed outcome instead of exceptions
  (Decision 1) and to do so additively (Decision 2).
- The closed three-way taxonomy and its exact codes (`HOSTOUT-001`).
- Capability requirements (`HOSTOUT-002`).
- The three admission/diagnostic decisions (`HOSTOUT-003`), including the
  explicit limitation that exhaustive dispatch is not yet compiler-enforced
  for the raw `usize` shape.
- The implemented native, Wasm, and interpreter lowering shape, including the
  V3 import/export names and separate checked callback/status handling.

**Not covered / explicitly deferred:**
- The network family (`net_send`/`net_recv`/etc.) — named by issue #228 but
  intentionally out of the first slice (Decision 2).
- A general try/catch or exception language feature.
- `std.jobs` composition wiring — left to the issue that lowers this
  document.


## Acceptance evidence and compatibility tests

`tests/useful_data/filesystem_v2_native.rs`,
`filesystem_v2_write_atomic_failure_collapses_into_undifferentiated_abort`:
compiles and runs generated C proving today's exact gap — a `write_atomic`
provider failure standing in for an "uncertain" condition produces the
identical `!semantic_success && status_code == 5` result and the identical
"no later operation runs" abort shape as an ordinary pre-publication
validation failure, with nothing in the generated carrier distinguishing
them. This remains a compatibility regression for the legacy V2 behavior: its
assertions are intentionally unchanged and are required alongside the V3
success/`NOT_PUBLISHED`/`UNCERTAIN` and invalid/unwritten callback tests before
acceptance can be considered complete, per this document's `HOSTOUT-001` table
and the repository's "add a success case and stable diagnostic regression
before or with the implementation" change protocol rule.

`src/filesystem_provider/tests.rs` additionally checks the checked provider
fixture and legacy scoped physical providers. Checked fixture controls prove
pre-commit refusal preserves the target, and a commit-ambiguous fixture may
have published. The Unix rename `EIO` mapping is phase-aware implementation,
not evidence of an injected physical syscall failure. The `project` harness `filesystem_v3` selector passed four local tests across
interpreter, native C11 at `-O0`/`-O2`, and Node Core Wasm, including all three
outcomes, nested invalid-path control flow, invalid/unwritten callback values,
provider status defects, and repeat invocation cleanup. Compact checked
example/test sources live in `tests/project/standard_library/filesystem_v3_sources/`;
the default `std/fs` package keeps its existing graph-construction bound.

## Future extensions

The raw builtin retains its bounded `usize` ABI; the source wrapper supplies
exhaustive variant matching. Outcome classification grants no additional
capability. Network transfer ambiguity, additional fallible operations and
provider-specific durability guarantees require their own reviewed contracts.
