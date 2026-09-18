# Public Generic Ownership Milestone v1

Status: open milestone, separately gated. Five of its nine prerequisite gates
are hosted green for one exact implementation commit; three more (PG-5, PG-6,
PG-7) now have real code and passing local gates but no hosted run and named
open gaps (see the gate table below). PG-9 remains undecided. No public
generic ownership surface is admitted, generated, published, or supported at
this commit. This document owns the milestone's identity, its gates, the
separation invariants, and the standing support/publication decision. It is a
charter, not evidence.

Audience: language, ABI, package, evidence, and promotion reviewers.

Every CI run on `main` since the recorded PG-8 commit has been cancelled
(`cancel-in-progress` plus a fast push cadence), so none of PG-5/PG-6/PG-7's
local evidence below is hosted evidence yet, and the recorded PG-8 green run
predates all of that code.

## Why this is a separate milestone

Public generic ownership is the surface on which a *foreign* consumer observes
a generic template, its ordered concrete arguments, the substituted field tree
of an owned value, and that value's allocation and failure settlement across a
target boundary. Nothing in that list is a consequence of admitting a generic
inside a SEMAPRAX body.

[Concrete Generic Owned-Byte Records v1](CONCRETE-GENERIC-OWNED-BYTE-RECORDS-V1.md)
and the GEN-06 contracts closed bounded *internal* generic semantics: exact
instance identities, ordered substitutions, ownership and call facts, cleanup
replay, and backend execution. Every observable parameter and result in those
profiles stays scalar or a borrowed byte slice; the template, the concrete
instance, the fields, the layout, and the owner remain internal to the body.
Closing more of that work produces no public generic signature, descriptor,
carrier, consumer, or support claim, and the reverse also holds: this milestone
may not be advanced by widening an internal admission profile.

Treating the public surface as a side effect of GEN-05 would fail four ways at
once. It would publish an unversioned type spelling as an interchange format;
it would let a display rename or an argument reordering change a foreign
calling convention silently; it would hand a consumer an owned allocation with
no stated settlement on failure; and it would convert a single green internal
Linux job into a cross-platform support claim. The milestone exists so each of
those becomes its own artifact with its own executable gate.

## Milestone identity

| Layer | Identifier |
| --- | --- |
| Milestone | `semaprax.public-generic-ownership.v1` |
| Roadmap workstream | ABI-09, [public generic programme](ROADMAP.md) |
| Prerequisite gates | `PG-1` through `PG-9` |
| Separation gate | `public_generic_ownership_milestone` in the projections harness |

The milestone identifier names the programme. It is deliberately not a Project
schema, profile, descriptor, carrier, or prelude version: a public generic
surface requires new versioned artifacts of its own rather than reinterpreted
Project v8, v9, or v11 bytes.

## Prerequisite gates

Each gate is independent, has one owning artifact, and is advanced only by that
artifact's executable evidence. The state column uses exactly three values:

- `Open` — nothing is implemented for it.
- `Implemented, local evidence` — the code and its executable gate exist and
  pass locally. No hosted run is recorded, so this is not hosted evidence and
  not a support claim.
- `Hosted green` — a hosted run and job are recorded in the owning artifact for
  an exact implementation commit.

PG-8 is what converts local evidence into hosted evidence; no other gate may
record `Hosted green` before it does. PG-9 may only move once every other gate
reads `Hosted green`.

| Gate | Requirement | Owning artifact | State |
| --- | --- | --- | --- |
| PG-1 | A new versioned target-neutral type grammar: closed vocabulary, injective canonical term, byte-exact render and parse, domain-separated digest, and fail-closed rejection of every construct outside the admitted surface | [Public Generic Type Grammar v1](PUBLIC-GENERIC-TYPE-GRAMMAR-V1.md) | Hosted green |
| PG-2 | Explicit template identity and ordered argument identities: persistent template declaration identity, declared arity, positional parameter owner and index, and digests that distinguish permutation, omission, duplication, and substitution | [Public Generic Type Grammar v1](PUBLIC-GENERIC-TYPE-GRAMMAR-V1.md) | Hosted green |
| PG-3 | Semantic compatibility rules: a closed classification over two grammar surfaces with explicit reasons, no compatibility inferred from a diff classification, and no version decision inferred from a classification | [Public Generic Compatibility v1](PUBLIC-GENERIC-COMPATIBILITY-V1.md) | Hosted green |
| PG-4 | Candidate ABI-delta evidence that selects the public generic signature, retains ordered arguments and substituted fields, and survives mutation, recovery, and independent byte-exact replay | [Public Generic Candidate Delta v1](PUBLIC-GENERIC-CANDIDATE-DELTA-V1.md) | Hosted green |
| PG-5 | Generated Rust, TypeScript/Wasm, C, and C++ consumers derived from the grammar, byte-deterministic, with no ambient authority | [Public Generic Consumers v1](PUBLIC-GENERIC-CONSUMERS-V1.md), [Public Generic Carrier v1](PUBLIC-GENERIC-CARRIER-V1.md) | Implemented, local evidence |
| PG-6 | Hostile metadata replay: forged, stale, truncated, reordered, and mutated grammar or descriptor bytes fail closed in every consumer route and in independent replay | [Public Generic Descriptor v1](PUBLIC-GENERIC-DESCRIPTOR-V1.md), [Public Generic Carrier v1](PUBLIC-GENERIC-CARRIER-V1.md) | Implemented, local evidence |
| PG-7 | Owned allocation and failure settlement across the boundary: bounded allocation, exact copy-out, sticky failure selection, canonical cleanup order, and equal checked behavior on interpreter, native C11, and Core Wasm | [Public Generic Settlement Obligations v1](PUBLIC-GENERIC-SETTLEMENT-V1.md), [Public Generic Carrier v1](PUBLIC-GENERIC-CARRIER-V1.md); also documented in [Public Generic Consumers v1](PUBLIC-GENERIC-CONSUMERS-V1.md#cross-engine-settlement-corpus-issue-162) | Implemented, local evidence |
| PG-8 | Cross-platform hosted evidence for the complete milestone corpus on Linux, macOS, and Windows, recorded for an exact implementation commit | The `public-generic-ownership-milestone` job in [CI required checks v1](CI-REQUIRED-CHECKS-V1.md) | Hosted green |
| PG-9 | An explicit support and publication decision naming the exact version, target, and consumer scope, with its prerequisite profile decisions | This milestone | Open |

PG-1 through PG-8 are prerequisites of PG-9, not substitutes for it. A complete
set of green prerequisite gates authorizes the decision to be *made*; it does
not make it.

### Gate scope notes

A gate moves only when the whole of it is done. Where part of a gate has landed
with its own artifact and its own executable gate, it is recorded here rather
than by advancing the row.

- **PG-5 and PG-6 — grammar half hosted green, calling half now implemented
  with local evidence only.**
  [Public Generic Metadata Consumers v1](PUBLIC-GENERIC-CONSUMERS-V1.md)
  generates a Rust, TypeScript/Wasm, C, and C++ consumer of the canonical
  metadata of a candidate surface. All four are compiled warning-free and run
  for real, and all four must refuse nine hostile documents — forged term
  length, reordered records, stale surface, truncation, and the rest — with the
  same closed reason as each other and as the Rust reference reader. That part
  is hosted green (see the PG-8 note below).

  A versioned [Public Generic Descriptor v1](PUBLIC-GENERIC-DESCRIPTOR-V1.md)
  and [Logical Carrier v1](PUBLIC-GENERIC-CARRIER-V1.md) now exist, with
  independent byte-exact replay, and all four languages generate a *calling*
  consumer (Rust #156, C11 #158, C++17 #159, TypeScript/Wasm #157) that
  invokes a real native or Wasm provider adapter and is compiled and executed
  locally (native: real `clang -O0`/`-O2` builds linked against
  `native::template::render_reference_provider`'s C output; Wasm: a real
  `WebAssembly.Instance` call). Re-run directly for this update: `cargo test
  --locked --test public_generic_native_adapter_v1` (16 passed, 3 ignored —
  the ignored cases are `#[ignore]`d sanitizer variants requiring a
  provisioned toolchain, not failures), `cargo test --locked --test
  public_generic_wasm_adapter_v1` (15 passed, 0 failed), and
  `sh tests/public_generic_native_adapter_v1/run_all_four_callers.sh` (issue
  #172's aggregate entry point; exit 0, printing one `AGGREGATE ... PASS`
  line per caller and the same honesty line reproduced above). A shared
  hostile corpus (#160) is checked
  identically across the Rust reference decoder, the native manifest, and all
  four consumers. None of this has a hosted CI run: every run on `main` since
  implementation commit `2ef043ba…` has been cancelled (`cancel-in-progress`
  plus a fast push cadence), so PG-8 has not been re-executed against any of
  it (tracked by #163). Three concrete gaps remain open and undecided:
  - every provider adapter (interpreter, native, Wasm) binds a **fixture**
    endpoint and **fixture** trusted descriptor/binding bytes, not a real
    function body generated from an admitted public-generic export — the
    codegen wiring from a verified descriptor to a callable native/Wasm
    function body does not exist yet, so no real monomorphized `.spx` public
    generic export has ever been called through this boundary end to end;
  - no compiled `.wasm` artifact implements the provider ABI (open /
    input_prepare / call / result_export / release); the TypeScript consumer
    calls a real Wasm function for the one reversal endpoint but keeps
    allocator/handle bookkeeping host-side in TypeScript, and the harness's
    own `.wasm` is a hand-assembled, committed test-only stand-in
    (`tests/public_generic_wasm_adapter_v1/reference_wasm_module.rs`), not a
    build of `src/public_generic_abi/wasm/**` (#229, human-blocked on a
    scope decision);
  - `5ac1331d` closed the gap this note used to record: all four generated
    calling consumers (Rust/C11/C++17 via the C11 layer, TypeScript/Wasm)
    now independently parse the bounded Descriptor-v1 frame envelope —
    exact frame count, per-field UTF-8, the three frozen schema/version
    literals — *before* the byte-exact trusted-descriptor pairing check, so
    extra frames, missing frames, truncation, invalid UTF-8, and an unknown
    schema/version are rejected as malformed framing rather than merely as
    a byte mismatch. Reordered and duplicated content fields are still
    caught only by the byte-exact pairing check (reordering or duplicating
    content necessarily changes the bytes), which reports the identical
    closed `DescriptorRejected` reason, so the observable refusal class
    matches either way. `tests/support/public_generic_hostile_corpus.rs`'s
    `structured_descriptor_cases()` — unknown schema, invalid UTF-8, stale
    program root, reordered context, duplicate context, truncated final
    frame, extra frame, overlong length claim, presentation-only rename —
    is now driven through real generated-and-executed Rust, C11, and C++17
    drivers (`tests/public_generic_native_adapter_v1/shared_hostile_corpus.rs`)
    and a real generated-and-executed TypeScript/Wasm driver
    (`tests/public_generic_wasm_adapter_v1/shared_hostile_corpus.rs`), each
    pinned against the same SHA-256 mutation bytes and the same Rust
    reference-decoder outcome. Cross-runtime replay
    (`binding_wrong_target_profile`) and cross-artifact replay
    (`binding_valid_for_different_artifact`) are covered the same way.
    Stale Project/ProgramRoot/source/export/public-surface associations are
    exercised at the reference-decoder layer
    (`descriptor/tests.rs::replay_rejects_a_cross_paired_descriptor_on_every_bound_field`)
    and, for `program_root`, through the shared corpus above; nothing about
    this layer's calling-consumer parity was untested before `5ac1331d`
    beyond those two content-reordering cases, which were already provably
    equivalent by construction (any content mutation changes the trusted
    pairing bytes).
  - Bounded, deterministic property/fuzz coverage now exists for both wire
    codecs: `descriptor::fuzz` and `carrier::fuzz`
    (`src/public_generic_abi/descriptor/fuzz.rs`,
    `src/public_generic_abi/carrier/fuzz.rs`) apply a fixed-seed, hand-rolled
    `xorshift64*` mutation engine (`fuzz_support.rs`; no `proptest`/
    `quickcheck` dependency, since adding one edits `Cargo.toml`, off this
    round's file lease) over 500 reproducible trials per codec, each
    bounded to at most 4 point mutations and a 16-byte length delta, and
    assert `decode`/`replay`/`decode_binding`/`replay_binding` never panic
    and never return a diagnostic code outside the small closed set each
    already documents. Any violation renders the exact offending bytes as a
    pasteable Rust literal in the assertion failure — the "persist minimized
    reproductions for any discovered distinct invariant" outcome #173 asks
    for — rather than a bare pass/fail. This is bounded generation over a
    hand-built fixture, not derived from a real checked generic export, and
    it runs only the reference codecs in-process; it does not drive the
    same mutated bytes through the four generated calling consumers (that
    remains the deterministic, individually-pinned `structured_descriptor_cases`
    corpus above, not a randomized one — running an unbounded random corpus
    through four spawned toolchains per trial was judged out of proportion
    to this round's scope and is not attempted here).

  Both gates therefore move from `Open` to `Implemented, local evidence`, not
  `Hosted green`.
- **PG-4 — route implemented, and it now describes a genuine generic export
  when one is named explicitly (issue #139).**
  [Public Generic Candidate Delta v1](PUBLIC-GENERIC-CANDIDATE-DELTA-V1.md)
  is candidate-bound and grammar-strict: an export is *described* only when the
  grammar spells every parameter and the result, so an entry in the delta is
  exactly a candidate public generic signature and nothing looser.

  The manifest-profile route still describes nothing generic, and that is a
  structural fact rather than a defect: every Project profile's admission
  eagerly lowers each declared export, and nested-owned-record derivation
  refuses any nominal with non-empty arguments outright, so no manifest profile
  can carry a generic `web_export` at all. The milestone's own generic fixture
  therefore still comes out all-excluded — and the gate asserts that its rendered bytes carry no template
  identity, no instance term, no record identity, and not even the grammar's
  instance sigil.

  What changed is that the classifier and descriptor producer work directly
  over the resolved program rather than over a manifest profile, so a function
  reachable from the entry closure can satisfy Boundary Profile v1 without ever
  being a `web_export`. `public_generic_delta_with_boundary_subjects` takes
  such subjects explicitly from the caller — never auto-scanned — merges them
  into the compared set, classifies each independently, and binds a real
  descriptor digest into a `facts.boundary_profile` section. The zero-subject
  call is the same route and is proven byte-identical to the original, so no
  existing report moved. The substantive record evidence still rides on a
  Project v9 record-returning export, where a real `add_record_field` change is classified
  `breaking` with the finding on the record that changed, with ordered
  arguments, substituted fields, and owned leaves retained across mutation,
  recovery, and byte-exact independent replay.
- **PG-7 — obligations specified and bound, execution now implemented with
  local evidence, cross-engine settlement partial.**
  [Public Generic Settlement Obligations v1](PUBLIC-GENERIC-SETTLEMENT-V1.md)
  derives, for one owned instance parameter, which owned leaves a boundary is
  accountable for, in which order, how each is discharged, and what is released
  when a transfer fails part way — and binds all of it to the compiler's own
  cleanup facts: the inventory's structural leaf order, its per-leaf liveness
  flags and drop lifecycles, and the plan's whole-parameter transfer unit. Any
  disagreement is a refusal, so a future boundary cannot quietly diverge from
  the ownership the compiler verified. [Public Generic Carrier
  v1](PUBLIC-GENERIC-CARRIER-V1.md) now adds a real boundary: a native C11
  physical adapter (#154), a Core Wasm physical adapter (#155), and a
  reference interpreter physical adapter (#162), each performing real
  allocation, transfer, copy-out, sticky failure selection, and canonical
  release against a fixture endpoint, each covered by its own local test
  suite including a full 0-13 (native) / 0-7 (Wasm) failure-injection matrix
  with zero-live-resource assertions. A shared cross-engine settlement corpus
  (`carrier::settlement_corpus`, #162) drives the interpreter and Wasm
  adapters through the identical case table and diffs semantic output,
  normalized trace, release order, and resource counters byte-for-byte — this
  is what caught two real defects this session, on both engines, where a
  physical free was performed without its matching logical trace event
  (Wasm input path, native result path; fixed and each pinned by a
  concrete-trace-contents regression test, not a bare success assertion).
  Re-run directly for this update: `cargo test --locked -p semaprax --lib
  public_generic_abi::carrier::settlement_corpus` — 9 passed, 0 failed.

  This is not yet the full PG-7 the milestone asks for:
  - native C11 O0/O2 now participates through the existing integration harness,
    and all routes load one committed case manifest. The
    [persisted settlement corpus](PUBLIC-GENERIC-SETTLEMENT-CORPUS-V1.md) adds
    native per-case peaks, real allocation-failure regression coverage,
    physical release indices, and portable replay. Its native continuation also
    checks stale aliases/provider recreation, sibling settlement, exact/+1
    identity/live-capacity limits and paired lifecycle replay. Physical phase evidence
    additionally covers actual result allocation/copy, nonconsuming export failure,
    explicit release statuses and an exact 16 MiB fixture. The consumer
    continuation adds C/C++ error propagation, bounded codecs, independent
    caller counters, replay and Rust explicit-settlement implementation/gates.
    This remains a fixture
    boundary, not a compiler-derived generic-program equivalence proof;
  - peak allocation/handle observations are now compared for native O0/O2,
    but not across all model heaps/registries. Existing logical trace
    differences remain explicit, and the Wasm model is not an actual compiled
    provider module;
  - **every adapter still binds a fixture endpoint**, not a function body
    codegenned from a real admitted public-generic export — the same gap
    named under PG-5/PG-6 above;
  - nested/multi-level owned records are not exercised in any adapter or the
    corpus; every adapter is flat-owned-`Bytes`-leaves only. Issue #119
    closed this session, but only for an unrelated internal
    owned-record-collection execution profile — wiring an admitted
    public-generic descriptor into a codegen-emitted function body, which is
    what would lift this specific limitation, remains unimplemented and is
    not what #119 covered (see the native adapter's own "Deferred scope" note
    in [Public Generic Carrier v1](PUBLIC-GENERIC-CARRIER-V1.md)).

  The gate therefore moves from `Open` to `Implemented, local evidence`, not
  `Hosted green`: no hosted CI run exists for any of this (every run on `main`
  since `2ef043ba…` has been cancelled), and #174 ("execute settlement on all
  admitted backends") is closed only for interpreter/Wasm parity plus
  independently-compiled native, explicitly short of full cross-engine
  settlement and a hosted run.
- **PG-8 — hosted green, and what it did and did not establish.** The
  `public-generic-ownership-milestone` job runs the whole milestone corpus on
  `ubuntu-latest`, `macos-latest`, and `windows-latest`, and it is a declared
  release blocker rather than an optional lane, so it cannot be satisfied
  vacuously. It resolves the consumer toolchains each host really has and
  prints them, because a language whose toolchain is absent is skipped and a
  narrower run must be visible rather than read as a pass. All three legs are
  green for implementation commit `2ef043ba1b989f49b256e456f71fb6e89068bf33`
  in [run 34594793245](https://github.com/wavect/semaprax/actions/runs/34594793245) — jobs 103248047092 (Linux), 103248046648
  (macOS), and 103248046983 (Windows) — and each leg's log records all four
  consumer toolchains, `rust`, `typescript`, `c`, and `cxx`, as exercised
  rather than skipped. This is hosted evidence for the corpus those gates
  own. It is not evidence for PG-5's calling consumers, PG-6's descriptor
  bytes, or PG-7's boundary settlement, none of which the corpus contains.

  Getting there found three real defects that a Unix-only run could not: the
  Windows checkout failed before any gate for want of `core.longpaths`; a CRLF
  checkout of the generator's templates silently stopped every placeholder from
  substituting, so generated consumers lost their declarations and embedded
  metadata; and the Windows UCRT's deprecation of the standard `fopen` broke
  the generated C and C++ consumers' `-Werror` build. Each was fixed at its
  cause and each is now pinned by a gate.

  This hosted run predates, and the job as it stands today still does not
  run, any of PG-5/PG-6's calling-consumer work (issues #156–#160, #172,
  #173) or PG-7's cross-engine settlement corpus (issue #162): confirmed by
  reading `.github/workflows/ci.yml` directly, the job's "Four-language
  metadata consumers and hostile replay" step is unchanged and still invokes
  only `cargo test --locked -p semaprax --test projections
  public_generic_consumers`. Extending this required job to cover the new
  work is the next step this milestone still owes; it is out of this update's
  file lease (`.github/workflows/**`), so the exact delta is recorded in
  `HANDOFF.md` instead.

## Separation invariants

These hold for every change to internal generic semantics, including changes
that are otherwise fully gated and hosted green.

- An internal generic admission never admits a public generic signature. The
  template, concrete instance, fields, layout, and owner stay inside the body,
  and every public export keeps its already-admitted signature.
- No existing descriptor, carrier, package, prelude, graph, or cleanup schema is
  reinterpreted to carry a generic surface. A public generic surface requires a
  new versioned descriptor and carrier.
- A green internal gate is never evidence for a PG gate, and a green PG gate is
  never evidence for another PG gate.
- Neither a CI label, a generated package, a registration, nor an archive is a
  support or publication decision. Only PG-9 is.
- The public projections named below must keep rejecting a generic signature
  with their exact recorded reasons until the owning PG gates are green. The
  milestone's separation gate asserts this executably, so an accidental
  widening reddens the build instead of becoming a silent public claim.

## Recorded public-boundary rejections

These are the exact facts the separation gate pins. They are rejections by the
current public projections, not a list of intended future spellings.

| Public projection | Selected generic surface | Recorded outcome |
| --- | --- | --- |
| [Canonical ABI report](ABI-REPORT-V1.md) | a generic function | excluded, reason `generic_function` |
| [Canonical ABI report](ABI-REPORT-V1.md) | a monomorphic function returning a concrete generic instance | excluded, reason `unsupported_result_type` |
| [C header emission](C-HEADER-V1.md) | the same two selections | excluded with the same closed reasons |
| Project v9 and v11 public API descriptors | a selected generic result | rejected before descriptor or target generation |
| [Wasm scalar exports](WASM-SCALAR-EXPORTS-V1.md) | a generic or generic-returning export | rejected with `SPX-W115` |

An exclusion is a closed report reason, never a partial admission. A rejection
is a diagnostic, never a backend accident.

## Where the milestone stands

Five gates are hosted green on Linux, macOS, and Windows for one exact
implementation commit. Three more (PG-5, PG-6, PG-7) have real code and
passing local gates but no hosted run. One (PG-8) needs a fresh run once
those three are ready to claim. PG-9 is undecided.

| Gate | Artifact | What remains |
| --- | --- | --- |
| PG-1, PG-2 | [type grammar](PUBLIC-GENERIC-TYPE-GRAMMAR-V1.md) | nothing; hosted green on three hosts |
| PG-3 | [compatibility rules](PUBLIC-GENERIC-COMPATIBILITY-V1.md) | nothing; hosted green on three hosts |
| PG-4 | [candidate delta](PUBLIC-GENERIC-CANDIDATE-DELTA-V1.md) | nothing; hosted green on three hosts. It describes a genuine public-generic signature only when one is named explicitly via `public_generic_delta_with_boundary_subjects` (#139, #161); no manifest-profile route admits one on its own |
| PG-5, PG-6 | [consumers](PUBLIC-GENERIC-CONSUMERS-V1.md), [descriptor](PUBLIC-GENERIC-DESCRIPTOR-V1.md), [carrier](PUBLIC-GENERIC-CARRIER-V1.md) | a hosted run; codegen wiring from a verified descriptor to a real callable function body on any backend (every provider still binds a fixture endpoint); a compiled `.wasm` implementing the full provider ABI (#229); #173's remaining descriptor-level hostile cases exercised through all four calling consumers, plus MSRV and the 16 MiB bound for foreign consumers (#226) |
| PG-7 | [settlement obligations](PUBLIC-GENERIC-SETTLEMENT-V1.md), [carrier](PUBLIC-GENERIC-CARRIER-V1.md); [cross-engine corpus](PUBLIC-GENERIC-CONSUMERS-V1.md#cross-engine-settlement-corpus-issue-162) | a hosted run; complete model/compiled-Wasm/consumer participation in the persisted settlement corpus; comparable all-engine peaks and logical traces; the same fixture-endpoint and nested-record limitations as PG-5/PG-6 above |
| PG-8 | the `public-generic-ownership-milestone` CI job | a fresh run at the exact commit where PG-5/PG-6/PG-7 land, once `main`'s CI stops being cancelled before completion; the recorded green run predates all of PG-5/PG-6/PG-7's code |
| PG-9 | this document | the decision itself, once the eight above are hosted green |

The shape of what is left is no longer "there is no versioned public generic
descriptor and carrier" — one now exists, with local evidence for all three
of PG-5, PG-6, and PG-7. What is left is: no code path anywhere compiles a
real function body from an admitted public-generic export (every physical
adapter still calls a fixture endpoint), no compiled Wasm artifact implements
the admitted public-generic provider ABI, and hosted closure remains unrecorded.
The private compiled C11 reference route below now exercises an in-module
multi-call fixture; it does not change either compiler admission or public ABI
status.

### TypeScript host-owned settlement continuation

The [TypeScript continuation](PUBLIC-GENERIC-SETTLEMENT-CORPUS-V1.md#typescript-host-owned-caller-continuation-issue-162)
adds immutable module authentication, explicit single-call ownership, bounded
framing, whole-result validation, primary/secondary cleanup evidence and
independently replayed host-caller observations. The seven shared semantic
cases now have fresh native C/C++ comparisons. These checks exercise the
hand-assembled reversal endpoint under two V8 tiers, not a compiled generic
provider ABI. Actual Rust-generator equality remains a separate required gate;
no new PG-7 completion or hosted-green claim follows from local template runs.

## Standing support and publication decision

As of 2026-09-11: **public generic ownership is not supported and not
published.** No stable C, Rust, WIT, Component, npm, Project, or package
representation of a generic template, instance, or owned generic value exists,
and none may be described as supported, hosted, or production-ready.

The decision is revisited only when all of the following hold together:

1. PG-1 through PG-8 are green for one exact implementation commit, each
   recorded in its owning artifact with its hosted run and job.
2. The named scope is explicit: which grammar version, which descriptor and
   carrier version, which consumer languages, which targets, and which
   platforms.
3. The prerequisite profile decisions it depends on are themselves decided
   rather than assumed.
4. Fresh evidence is required for later code changes instead of attributing
   them to this milestone's commit.

Partial completion changes nothing. Eight green gates and an unmade decision
still mean unsupported and unpublished.

**Reverified 2026-09-18 against `main` at `e02ee0ef`, for issues #165 and
#141.** The 2026-09-11 conclusion is unchanged: still not supported, still
not published. Nothing below is a new decision; it is the prepared record
those two issues ask for, evidenced against current `main` rather than copied
from either issue's own text. Only a named maintainer may convert the
recommended option into an approved one, by posting the filled review-comment
template each issue requires.

## PG-9 prepared decision record

### Scope note: #165 and #141 are the same decision, two angles

#165 asks for the PG-9 decision for the whole Public Generic Ownership v1
milestone (PG-1 through PG-9). #141 (`SPX-AI-042`) asks for the same decision
restated for the specific slice #140 (`SPX-AI-041`) executed: the generic
*callable boundary* — real calling consumers, malformed-descriptor rejection,
and settlement, as opposed to the grammar/metadata half that was already
hosted green before #140 started. They are not independent: #141's own gate
is "#140 is accepted," and #140's own closing comment states plainly that its
four residual cells "are owned by other open issues (#173, #229)," so #141
cannot honestly move ahead of #165. There is no scope in which #141 would
recommend a different support/publication state than #165; this record
answers both from one evidence base and says so once rather than twice.

### Gate-by-gate table, verified against current `main`

Evidence kind uses the vocabulary this task requires: **hosted** (a completed
GitHub Actions run on a hosted runner), **local** (a command run on a
developer machine only), **proof-only** (a mathematical/property argument
with no execution), **absent** (no evidence exists for the claim).

| Gate | Passes? | At what head | Evidence kind | Source |
| --- | --- | --- | --- | --- |
| PG-1 (type grammar) | Yes | `2ef043ba1b989f49b256e456f71fb6e89068bf33` | Hosted (Linux/macOS/Windows) | [run 34594793245](https://github.com/wavect/semaprax/actions/runs/34594793245), jobs 103248047092/103248046648/103248046983 |
| PG-2 (template/argument identity) | Yes | same commit/run as PG-1 | Hosted | same run |
| PG-3 (compatibility rules) | Yes | same commit/run as PG-1 | Hosted | same run |
| PG-4 (candidate delta) | Yes | same commit/run as PG-1 | Hosted | same run |
| PG-5 (4-language calling consumers) | Grammar/metadata half only | `2ef043ba…` (grammar half); calling half at `main` (local only) | **Split**: grammar half hosted, calling half **local only** | milestone doc "Gate scope notes"; #140's audit (`e31a3fe2`): 40/2/3 and 22/1/1 local pass/fail/ignore counts, 3 failures environmental (`python3` shim), not product defects |
| PG-6 (hostile descriptor/carrier replay) | Grammar half only | same split as PG-5 | **Split**: grammar half hosted, descriptor/carrier hostile corpus **local only** | #173 still OPEN; #140 comment: "structured_descriptor_cases… driven through all four real compiled consumers," local |
| PG-7 (cross-engine settlement) | Partial (4 of 8 required engines/consumers) | `main` | **Local only** | #162 still OPEN; its own comment: "The acceptance list names eight engines and consumers. Four are now covered." Generated Rust/TS/C11/C++17 callers not yet in the corpus |
| PG-8 (hosted cross-platform run for the *complete* corpus) | No — only the **narrower**, pre-#140 grammar/metadata corpus is hosted green | `2ef043ba…`, a commit that **predates** all PG-5/PG-6/PG-7 calling, hostile-carrier, and settlement code | **Hosted, but scope-stale** | Milestone doc, verified directly against `.github/workflows/ci.yml`: the job's consumer step "is unchanged and still invokes only `cargo test --locked -p semaprax --test projections public_generic_consumers`" — it does not run the new work at all |
| PG-9 (the decision) | No | — | **Absent** | #165 OPEN, #141 OPEN, both unclosed by any maintainer comment |

Three gates that read "local only" above are not close to hosted: #163 (host
matrix refresh) is OPEN with one preflight-tooling commit landed
(`1d2a3e09`) and states explicitly "#162 completion and fresh three-host
expanded corpus/evidence are still required." #164 (freeze the release
candidate) is OPEN and has not started — it depends on #163. #175 (widen the
release-blocking job, P1) is OPEN. So the chain PG-5/6/7 → #163 → #164 → #165
has its first two links unmet, not merely its last one.

Two additional blockers sit underneath PG-5/PG-6/PG-7 rather than beside
them:

- **#229** (OPEN): no compiled `.wasm` artifact implements the public-generic
  provider ABI (`open`/`input_prepare`/`call`/`result_export`/`release`).
  `WasmProvider` is an in-process Rust model; the TypeScript consumer keeps
  allocator/handle bookkeeping host-side. The one thing that *is* newly
  real — a genuinely compiled `.wasm` scalar byte-reversal export via
  `build_web_with_scalar_exports` — is explicitly a "bounded, labelled
  stand-in," not the provider ABI, per #229's own second audit. That audit
  also found the blocker is architectural (`SPX-W115` closes both the byte-
  and scalar-export Wasm profiles to this shape) and, one level further back,
  that no manifest/Project profile admits a generic `web_export` at all yet
  — so a provider cannot even be *derived* from a checked generic export
  today, compiled or not. #229 is flagged `HUMAN_BLOCKED` on a target-profile
  design decision, not a bounded-worker task.
- **Every physical adapter (interpreter, native, Wasm) still binds a fixture
  endpoint**, not a function body generated from a real admitted
  public-generic `.spx` export. No real monomorphized public generic export
  has ever been called through this boundary end to end. This is stated in
  four places in the source itself
  (`src/public_generic_abi/native.rs:25`, `wasm/provider.rs:85-86`,
  `interpreter.rs:97`, `native/provider_body.c:22`) and confirmed live in the
  `examples/everyday-agent-project` Agent product added today
  (`f4c5327d`, 2026-09-18): its own commit message states the real
  public-generic consumer call and provider execution are "blocked on #162
  and #163 (both open, P0)," and that the fixture provider used in testing
  is deliberately named `unsupported-unpublished`.

**One correction to the milestone doc's own "what remains" table above**: it
still lists "MSRV and the 16 MiB bound for foreign consumers (#226)" as
outstanding under PG-5/PG-6. #226 is **closed** (`d9410607`) — the generated
Rust consumer now builds against the pinned MSRV toolchain and the native
provider's true payload ceiling was proven and reconciled with the documented
16 MiB bound (a real cross-implementation divergence was found and fixed
under the follow-up #250, also closed). That work is done, locally verified,
not hosted, and does not change the overall recommendation — it just means
the residual-gap list above is one item shorter than the milestone doc's
existing table records. This is the kind of drift this record exists to
catch: it runs in the *optimistic* direction here (a closed issue still
listed as open work), which is the opposite of the backlog's usual bias and
is called out explicitly per this task's instructions.

### Exact scope the decision would cover, if approved

**Admitted semantic scope** (all "v1"): monomorphic public generic signatures
only, no runtime generic specialization; one owned instance parameter with
flat (non-nested) owned `Bytes` leaves only — nested/multi-level owned
records are not exercised in any adapter; admitted Copy scalar arguments per
[Public Generic Type Grammar v1](PUBLIC-GENERIC-TYPE-GRAMMAR-V1.md); bounds
`MAX_BYTES_PER_LEAF` = 64 KiB, `MAX_OWNED_LEAVES_PER_INSTANCE` = 256,
`MAX_TOTAL_PAYLOAD_BYTES` = 16 MiB; synchronous and effect-free only — no
cancellation, concurrency, callbacks, borrows, resources, or generic
variants; sticky failure selection and canonical reverse cleanup order.

**Ownership rules**: an owned call stages arguments left to right and
transfers them together at its declared commit boundary (repository
invariant), enforced identically by [Public Generic Settlement Obligations
v1](PUBLIC-GENERIC-SETTLEMENT-V1.md) and bound to the compiler's own cleanup
facts; any disagreement is a refusal.

**Allocator responsibility**: the provider (native/Wasm/interpreter adapter)
owns input/result leaf allocation and release; the native adapter's own
allocator headroom (registry/bookkeeping bytes) is distinct from the logical
16 MiB payload bound (see #250, closed, for the reconciliation).

**Error/failure semantics**: closed reason vocabulary, sticky primary status,
deterministic secondary cleanup evidence, zero live resources after every
terminal case — proven locally for interpreter/native-O0/native-O2/Wasm-model
parity (`carrier::settlement_corpus`, 9/9 local), not yet for any of the four
generated calling consumers.

**Target/toolchain versions**: native C11 (`clang`, both `-O0`/`-O2`), Core
Wasm (model only — no compiled artifact implements the provider ABI, see
#229), Rust generated consumer pinned to MSRV 1.88 (proven locally,
`d9410607`), TypeScript/Wasm via `tsc` 5.8.3 (pinned in CI preflight,
`1d2a3e09`, itself not yet exercised against the full corpus), C++17.
Hosted-green platform evidence exists **only** for the narrower pre-#140
grammar/metadata corpus, on `ubuntu-latest`/`macos-latest`/`windows-latest`
at `2ef043ba…` — it says nothing about the calling, hostile-carrier, or
settlement work, all of which has run only on one developer's macOS arm64
host.

**Explicitly excluded**: generic variants, borrowed aggregates, resources,
effects, callbacks, concurrent or distributed calling, runtime
specialization, any manifest-profile-derived generic `web_export` (none
exists), any compiled Wasm provider ABI, any published package of any kind.

### What would have to become true to change this decision

Each item is a precondition, tied to the issue that owns it. None is
optional; #165 states that a missing required gate makes "the only valid
current decision" retain unsupported/unpublished.

1. **#173** — hostile descriptor/carrier replay proven through all four
   *generated* calling consumers (not only the reference decoder), closed.
2. **#229** — a maintainer-authorized target-profile decision on the
   compiled Wasm provider ABI, then an actual compiled `.wasm` artifact
   implementing `open`/`input_prepare`/`call`/`result_export`/`release`,
   closed.
3. **#140** — the callable-boundary/malformed-descriptor matrix accepted;
   its own last comment says it is blocked purely on #173 and #229 above,
   not on new code of its own.
4. **#162** — the remaining four engines (generated Rust/TypeScript/C11/C++17
   callers) added to the cross-engine settlement corpus, closed.
5. **#175** — the release-blocking `public-generic-ownership-milestone` CI
   job widened so PG-5/PG-6/PG-7 selectors are mandatory on every host, not
   only the old grammar/metadata step.
6. **#163** — one fresh, complete hosted run of the *widened* job on Linux,
   macOS, and Windows, for one exact commit, recorded with real run/job IDs.
7. **#164** — exact-head release-candidate convergence: no commit lands
   between the frozen SHA and the evidence claim, full local+hosted gate
   convergence, a frozen evidence packet.
8. **#165 / #141** — only after all seven above: a named maintainer records
   the filled review-comment template (`Decision:`, `Exact candidate SHA:`,
   `Hosted evidence run/jobs:`, `Supported state:`, `Published
   state/channels:`, …) as an issue comment. A thumbs-up is explicitly not
   sufficient per #165's own text.

Every one of 1–7 is an **open** GitHub issue today (verified via `gh issue
view`, 2026-09-18). None is in progress toward completion in a way that
changes the recommendation below.

### Recommended option

**Option A — remain unsupported and unpublished**, per #165's own decision
menu. This is not a preference; it is the only option the evidence supports,
because gates PG-5, PG-6, PG-7, and PG-8-for-the-new-corpus are not hosted
green, and PG-9 itself requires all eight to be. Options B/C/D (experimental
preview, full support, or a split decision) all presuppose evidence this
repository does not yet have.

**Support state**: `unsupported` (repository's closed vocabulary — see
`docs/COMPLETION-MATRIX.md`'s "Partial" / status-tooling conventions; no
`experimental-preview` or `supported-preview` label is warranted because no
consumer package or provider artifact has ever been distributed to anyone
outside this repository).

**Publication state**: `unpublished`. No package registry, GitHub prerelease,
toolchain archive, or generated-source channel carries any public-generic
descriptor, carrier, consumer, or provider artifact. A generated package
existing under `tests/public_generic_*` or in a local `target/` build is not
publication.

**Rationale in one sentence**: three of the milestone's nine gates (PG-5,
PG-6, PG-7) have only local evidence, one more (PG-8) is hosted green for a
commit that predates the code those three gates need, and #165 states its
own default for exactly this shape of evidence gap.

### Identity and authority (to be completed by the approving maintainer)

- Decision identifier/version: unassigned — no decision has been recorded.
- Decision date: unassigned.
- Authorized approver(s): unassigned — #165 and #141 both require a named
  Semaprax maintainer; this record was prepared by an agent and carries no
  approval authority.
- Exact candidate commit SHA: unassigned — no candidate has been frozen
  (that is #164's undone job).
- Exact hosted workflow run/job IDs for the *complete* corpus: unassigned —
  none exists yet; PG-8's only hosted run (`34594793245`) predates PG-5/6/7.
- Release-candidate evidence packet: does not exist — #164 has not started.

### Packaging, integrity, compatibility, and security posture

Not applicable while the recommendation is unsupported/unpublished: there is
no checksum, signature, notarization, reproducible-build, versioning,
deprecation, vulnerability-reporting, or revocation posture to record,
because nothing is published. Recording any of those fields now, before
publication is authorized, would itself be the kind of premature claim this
task and #165 both warn against. These fields become required inputs to the
*next* revision of this record, at the point a maintainer selects Option B,
C, or D.

### Nonclaims (unchanged by this record)

No runtime generic specialization; no generic variants, resources, or
borrowed aggregates; no ambient publication authority; no universal
target/platform support; no automatic semantic-version decision; no
compiled Wasm provider ABI; no compiler-derived generic export reaching any
adapter; no guarantee beyond the exact bounded profile described above; no
reinterpretation of Project v8/v9/v11 formats; no distributed/concurrent
calling; no hidden allocator ABI.

## Nonclaims

This document admits no syntax, defines no descriptor, carrier, package, or
calling convention, generates nothing, executes nothing, and grants no source,
filesystem, process, network, execution, signing, publication, or registration
authority. It does not promote, deprecate, or reinterpret any existing profile,
and it is not evidence that any gate has passed. The
[completion matrix](COMPLETION-MATRIX.md) owns product status; the
[quality gates](QUALITY-GATES.md) own required verification.

### Native admission continuation

The [single-owner continuation](PUBLIC-GENERIC-SETTLEMENT-CORPUS-V1.md#native-single-owner-admission-continuation-issue-162)
adds an executable refusal boundary for foreign-thread and reentrant misuse,
thread-local fault/diagnostic isolation, last-provider owner handoff and bounded
non-recycled thread identities. It exercises real C11 allocation/call/export/
release under pthread test contention, with zero-resource assertions and fresh
replay. This is enforcement of the synchronous non-concurrency policy, not
admission of concurrency or cancellation. PG-7 remains partial: compiler-derived
generic subjects, the admitted compiled Wasm provider ABI, complete four-language
participation and all-engine settlement equality are still separate requirements.

### Compiled reference continuation

The [compiled C11 reference continuation](PUBLIC-GENERIC-SETTLEMENT-CORPUS-V1.md#compiled-c11-reference-provider-inside-core-wasm-issue-162)
now places the existing reference provider's allocator, handle registry,
copy-in, endpoint, staging, export and release inside a real Core Wasm module.
It executes the same shared C assertions and canonical carriers as native
O0/O2, plus a separately checked raw multi-call transport. No host import
performs ownership work. Exact results, logical traces, releases, statuses and
logical resource counts agree; pointer-width-dependent byte peaks remain
reported separately. This supersedes a blanket assertion that no compiled
reference provider lifecycle is exercised. It does **not** supersede #229's
compiler-derived public-generic ABI requirement, migrate the generated
TypeScript caller, or constitute checked nested/Copy-scalar generic semantics.
The PG-7 row and unsupported/unpublished decision are not advanced.
