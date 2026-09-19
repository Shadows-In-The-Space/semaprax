# Public Generic WIT Type Projection v1

Status: implemented bounded projection, plus a compatibility/delta report
over two projections and an opt-in validation of the emitted WIT against a
real Component Model toolchain. Local evidence only, no hosted CI run
recorded. It projects types and nothing calls it.

Audience: ABI, WIT/Component, package, and evidence reviewers.

A documentation-tracked slice of issue #176, gated behind PG-9 of the
[Public Generic Ownership milestone](PUBLIC-GENERIC-OWNERSHIP-MILESTONE-V1.md).
**Public generic ownership is not supported or published, and this document
does not change that.** No public generic export exists, no compiled `.wasm`
implements the provider ABI (open issue #229), and no engine has executed a
component built from this projection. What exists is a deterministic,
refusal-total *type* projection from an already-checked Boundary Profile v1
admission to WIT `record`/`resource` text.

Implementation: [`src/public_generic_abi/wit_projection.rs`](../src/public_generic_abi/wit_projection.rs).

## Why this exists before PG-9

Issue #176 asks for a WIT projection of the "accepted public-generic scope."
At the audit baseline (`ae25c6a4`, 2026-09-11) that scope is, per the
milestone's own standing decision, **empty**: no public generic export is
admitted, generated, published, or supported. What the milestone *does* have,
hosted green, is the [Public Generic Type Grammar
v1](PUBLIC-GENERIC-TYPE-GRAMMAR-V1.md) (PG-1/PG-2) and the [Public Generic
Boundary Profile v1](PUBLIC-GENERIC-BOUNDARY-PROFILE-V1.md) classifier — a
read-only admission predicate over already-checked HIR that computes exactly
which record instances a candidate export's signature would reach, without
admitting a public surface.

This document and its module project *that* — a classifier admission's
already-computed record closure — into WIT text. It is useful evidence toward
issue #176 (the mapping-table and naming halves of its scope) without
overclaiming the calling-convention, component-binary, or support halves,
which remain blocked on PG-9 and on #229 respectively.

## Scope: the whole mapping table

The type grammar admits exactly three term shapes, and only three: a Copy
scalar, direct owned `Bytes`, and a fully concrete authored record instance.
Every other type the grammar could name — an unsubstituted type parameter,
`string`, `str`, `Slice<u8>`, `unit`, an inline byte array, a function type, a
compiler-owned nominal (`Option`, `Result`, `Vec`, `Box`, `Iter`, ...), or an
authored class/variant/resource — is refused by the grammar itself, with its
own closed reason, before this projection is ever reached. This module
therefore has exactly this mapping table, and no more:

| Grammar term | WIT projection | Notes |
| --- | --- | --- |
| `i64` | `s64` | |
| `i32` | `s32` | |
| `u8` | `u8` | |
| `char` | `char` | |
| `f32` | `f32` | |
| `f64` | `f64` | |
| `bool` | `bool` | |
| `usize` | refused (`SPX-PGWIT101`) | no WIT primitive has a portable pointer width; approximating it as `u32`/`u64` would silently pick a width the source type never specified |
| `bytes` (owned `Bytes`) | `own<spx-owned-bytes>` | a handle to one shared opaque `resource`, never `list<u8>` — see below |
| a concrete record instance | a WIT `record`, one field per substituted field, recursively projected | |

Issue #176's in-scope list also names variants, owned/borrowed strings,
`Option`, `Result`, and authored resources. None of those can reach this
module today, because the grammar itself does not admit them yet; widening
the grammar to admit any of them is its own new grammar version with its own
gates (stated already in [Public Generic Type Grammar
v1](PUBLIC-GENERIC-TYPE-GRAMMAR-V1.md#admitted-vocabulary)), and only then
would this projection gain a corresponding new mapping row. This document
does not invent a spelling for any of them in the meantime.

### Why `bytes` is a resource, not `list<u8>`

WIT's `list<u8>` is a by-value component type: the canonical ABI copies it
across the boundary and the receiving side owns an ordinary value, with no
notion of an explicit release. SEMAPRAX's owned `Bytes` is the opposite: a
single unique owner, sticky failure selection, and a canonical cleanup order
the compiler verifies and the [Public Generic Settlement
Obligations](PUBLIC-GENERIC-SETTLEMENT-V1.md) work derives field by field.
Projecting it as `list<u8>` would silently hand a foreign consumer a value
with GC/copy semantics and let the Component Model runtime believe it settled
ownership the compiler never delegated to it — exactly the assumption issue
#176 names as explicitly out of scope. Projecting it as an owned resource
handle (`own<spx-owned-bytes>`) keeps the explicit-close discipline visible in
the WIT surface itself, even though no physical resource destructor exists
behind it yet (that is calling-convention and adapter work, blocked on PG-9
and #229, not a type-projection concern).

## Naming

Every WIT identifier is `spx-` followed by the lowercase hexadecimal UTF-8
bytes of a persistent identity — the same convention
[`src/project/scalar_wit.rs`](../src/project/scalar_wit.rs) already uses for
the Project-v1 scalar WIT interface's exported function names:

- a record's name hexes its own canonical [Public Generic Type
  Grammar v1](PUBLIC-GENERIC-TYPE-GRAMMAR-V1.md) term (e.g.
  `@23:mod.pair<@23:mod.leaf<>,i64>`), not its declaration id alone, so two
  different concrete instantiations of the same template are two different
  WIT records;
- a field's name hexes its own persistent field declaration id, not its
  display name.

Hex framing of an already-injective grammar term (injectivity is proved in
[Public Generic Type Grammar v1](PUBLIC-GENERIC-TYPE-GRAMMAR-V1.md#injectivity))
is itself injective: two distinct byte strings hex to two distinct names,
independent of length, punctuation, or any grammar delimiter one of them might
contain. No hashing, truncation, or normalization step is in this path to hide
a collision. A display-only rename of a record, its type parameters, its
fields, or the exported function that reaches it leaves every WIT identity
here unchanged, because the grammar term and the stable field id it hexes
already exclude every display name.

## Determinism

[`project_admitted_subject`] takes its closure directly from
[`AdmittedSubject::record_closure`](../src/public_generic_abi/classifier.rs)
— a `BTreeMap<String, InstanceFacts>` keyed by canonical term the [Public
Generic Boundary Profile v1](PUBLIC-GENERIC-BOUNDARY-PROFILE-V1.md) classifier
already computes for candidate-delta and settlement use. Visiting a
`BTreeMap` is ordered by key; visiting a record's fields walks the
already-ordered `Vec<FieldFact>` the classifier produced. Nothing in this path
reads a `HashMap`, the process environment, the clock, or randomness, so the
same admitted subject renders byte-identical WIT text on every call — the
projection's own test asserts this directly by projecting the same subject
twice and comparing both the structured result and the rendered bytes.

Records are emitted in dependency order (a record's own dependencies are
always emitted, and reach the closure lookup, before the record itself),
computed by recursion over each record's fields rather than by the
closure map's own top-level key order — which is a distinct thing to prove,
demonstrated by picking declaration ids whose canonical terms sort in the
*opposite* order from their dependency (`aaa_pair` contains `zzz_leaf` but
sorts before it), so a projection that only followed the map's key order
would emit the dependent record first and be caught doing so.

## Lossless or explicitly refused — never approximated

Two refusal paths exist, and each carries a specific, checked reason rather
than an approximation:

- **`usize`** (`SPX-PGWIT101`): the message names the exact rejected scalar.
  The regression test compiles a real program whose classification succeeds
  (proving the refusal is this module's, not an earlier grammar/classifier
  check reused under a new name), then confirms only the projection step
  fails, with this code, and that the message contains `usize`.
- **a record instance absent from the supplied closure** (`SPX-PGWIT102`):
  the closure is the caller's explicit input, exactly like the "explicit
  closure, never auto-scanned" convention [PG-4's candidate
  delta](PUBLIC-GENERIC-CANDIDATE-DELTA-V1.md) already established; a missing
  member is refused by name rather than silently treated as an empty/opaque
  type. A defensive third code (`SPX-PGWIT103`) additionally catches an
  internally inconsistent closure (two different facts under one canonical
  term, or a closure entry whose own term disagrees with its map key) — not
  reachable through the classifier's own construction, but refused rather
  than trusted if a future caller assembles a closure by hand.

Capacity (`SPX-PGWIT104`, the rendered WIT exceeding
[`MAX_WIT_PROJECTION_BYTES`] = 65,536 bytes, or the shared record-nesting
depth bound the type grammar already enforces) is a refusal, never a
truncation.

## Round-trip

[`parse_wit_projection`] is an independent, bounded profile parser for
exactly this module's own rendering — the same "independent bounded parser
accepts only that profile" convention the private WIT/Component harness in
[WIT-COMPONENT-BOUNDARY-V1](WIT-COMPONENT-BOUNDARY-V1.md) already uses, not a
general WIT-text parser, and not cross-checked against an external
`wit-parser`/`wasmparser` crate (adding one would touch `Cargo.toml`, out of
this work's lease). Every identifier and type-text token is scanned by its
exact legal character set rather than searched for with an unbounded
substring search, so a single corrupted delimiter cannot let parsing
resynchronize past it onto a later, unrelated line and silently accept the
wrong text as the field that was actually mutated — an early draft of this
parser had exactly that bug, and the hostile mutation test below is what
caught it.

The round-trip regression compares the **parsed** structure against the
**pre-render** `WitTypeProjectionV1` facts that produced the text — never
against a second call to the renderer — so a renderer/parser pair that agreed
with each other but silently drifted from what was actually intended to be
projected could not pass this test by construction.

Hostile cases: truncating the rendered text by a handful of trailing bytes,
corrupting one field's `: ` separator, and appending one trailing byte after
the closing `world` block are each rejected with `SPX-PGWIT105`, independently
of each other.

## Owned-leaf census agreement

A projection nothing checks is documentation that drifts. The rendering above
is syntactically valid WIT whatever it contains: a projection that dropped a
`Bytes` field, reached a record the classifier did not, or attached a leaf
under a different field identity would still render, and a foreign consumer
reading it would build a value whose owned-leaf inventory silently disagrees
with the carrier the compiler actually verified.

[`leaf_census`](../src/public_generic_abi/wit_projection/leaf_census.rs)
closes that gap. It recomputes the owned-leaf inventory a **second,
independent way** — walking the rendered projection's `WitRecordV1` /
`WitFieldV1` structure from the input and result roots, framing each leaf's
path as the grammar's own `@<len>:<id>` segments joined by `/` — and refuses
unless the result is element-for-element identical to
`InstanceFacts::owned_leaves`, which
[`src/public_generic_type.rs`](../src/public_generic_type.rs) derived by
walking substituted `ResolvedType`s instead. The two derivations share no
code path, so their agreement is evidence rather than a tautology.

`project_admitted_subject` runs the check before returning, so the gate is at
the producer: a disagreeing projection is refused, never handed back as
plausible WIT.

The check's identity framing is a deliberate second spelling of the grammar
module's private `write_identity`. That is not a silent duplicate: the
agreement comparison is exactly what fails if the two spellings ever drift,
on the very next projection.

### Bounds and refusals

The walk is structural, so it expands each record *reference* (a record
declared once can be reached from several places). It is bounded by the same
[Public Generic Boundary Profile v1](PUBLIC-GENERIC-BOUNDARY-PROFILE-V1.md)
numbers the carrier is bounded by, never by a number chosen here:
`MAX_VISITED_NODES_PER_INSTANCE`, `MAX_NESTING_DEPTH`, and
`MAX_OWNED_LEAVES_PER_INSTANCE`.

| Code | Refusal |
| --- | --- |
| `SPX-PGWIT106` | the projected structure's owned-leaf inventory is not the descriptor's, for the input or the result; the message names the role and either the first differing index with both paths, or both counts |
| `SPX-PGWIT107` | the census walk exceeded a boundary-profile bound — a refusal, never a truncated census |
| `SPX-PGWIT108` | a field names a record type the projection never declared |

### Evidence

Each negative case mutates the *structured* projection and re-runs the check
against unchanged classifier facts, so each proves the gate catches one
specific corruption rather than that a well-formed projection passes:
a dropped owned-leaf field, a leaf reached under a different field identity,
a field naming an undeclared record, and one more owned leaf than the profile
admits. The positive case pins the expected inventory itself
(`@24:wit_projection.pair.left/@24:wit_projection.leaf.head`) before
comparing, so a vacuous empty-equals-empty pass is impossible.

A **byte golden** pins the rendered WIT's exact length and SHA-256. The
pre-existing determinism test only proved two calls in one process agree;
the golden additionally pins layout, record order, and identifier encoding
across refactors and across machines.

**Evidence class: local, re-runnable.** No hosted run and no Component Model
runtime is involved in the census gate; no `wasm-tools`, `wit-bindgen`, or
`wasmtime` invocation is part of it. A separate, opt-in `wasm-tools`
validation of the emitted text is described under [Validation against a real
Component Model toolchain](#validation-against-a-real-component-model-toolchain);
it is `#[ignore]`d, so a default `cargo test` still runs no external tool.

## Compatibility and delta reporting

Implementation:
[`src/public_generic_abi/wit_projection/compat.rs`](../src/public_generic_abi/wit_projection/compat.rs).

Issue #176's seventh implementation step asks for "compatibility checks for
field/case addition, reordering, ownership change, and identifier-preserving
display rename". `compare(baseline, candidate)` produces a deterministic
[`WitCompatibilityReportV1`] over two projections; `require_compatible` is the
same comparison as a gate.

Comparing two renderings' bytes answers only "did anything change". A reviewer
needs the *kind*, because the kinds are not interchangeable.

| Delta | Class | Why |
| --- | --- | --- |
| `record-added` | compatible | a new declaration; no existing record's field list, order, or ownership moved, so no consumer already bound to the baseline can observe it |
| `record-removed` | breaking | a consumer may already name that declaration |
| `field-added`, `field-removed` | breaking | a Component Model record's canonical field sequence is rewritten; a baseline consumer reads later fields at the wrong positions. Adding a field is **not** additive the way adding a declaration is |
| `field-reordered` | breaking | same ids, same types, same count — only position moved, which is exactly what a set-based or name-sorted comparison would miss |
| `field-ownership-changed` | breaking | a leaf crossed between a by-value type and `own<spx-owned-bytes>`: *who runs cleanup* moved across the boundary. Its own delta kind, never folded into a type change |
| `field-type-changed` | breaking | a type change that stays on one side of the ownership boundary |
| `owned-bytes-resource-added`/`-removed` | breaking | the world's shared `resource` declaration appeared or disappeared |
| `world-identity-changed` | breaking | `package`, `interface`, `world`, `input-type`, or `result-type`; the identity *is* the contract |

An **identifier-preserving display rename has no row**, because it is not a
delta. Every WIT identifier is the hex of a persistent identity — a canonical
grammar term, or a stable field declaration id — and neither carries a display
name, so two programs differing only in display names render byte-identical
WIT. The test
`an_identifier_preserving_display_rename_is_not_a_delta_at_all` renames every
record, field, and type parameter while holding every `@id` fixed and asserts
the two renderings are equal byte for byte and the report is empty.

Field *position* is compared among the fields the two records share, so an
insertion does not report every later field as reordered, and a genuine
reorder is not masked by an unrelated insertion earlier in the list.

| Code | Refusal |
| --- | --- |
| `SPX-PGWIT121` | the two projections do not share one `wit-projection` schema, so no delta between them is meaningful |
| `SPX-PGWIT122` | more than `MAX_REPORTED_DELTAS` (512) deltas — refused, never truncated, since a partial delta list presented as a complete one would understate a break |
| `SPX-PGWIT123` | `require_compatible` found at least one breaking delta |

### Evidence

Sixteen tests in
[`compat/tests.rs`](../src/public_generic_abi/wit_projection/compat/tests.rs).
Every positive case compares two projections the compiler really produced from
two real `.spx` fixtures, so the comparator cannot agree with a hand-written
expectation while disagreeing with the projector. The controls that make them
mean something:

- a projection compared against itself reports **no** delta, so every "exactly
  these deltas" assertion is not satisfied by a comparator that flags
  everything;
- the reorder fixture changes ids, types, and count not at all, so a
  set-comparison implementation fails it;
- a type change that does *not* cross the ownership boundary asserts it is
  reported as `field-type-changed` and **not** as an ownership change, so
  `field-ownership-changed` cannot be emitted for every type difference;
- each refusal has a positive control beside it: the schema-mismatch test
  re-compares the same pair once the schemas agree, and the capacity test
  asserts that exactly `MAX_REPORTED_DELTAS` is accepted, so the bound is the
  documented one and not off by one in the permissive direction.

Every fixture keeps [`BASELINE`]'s line layout, because a canonical grammar
term carries a declaration coordinate; changing the number of preceding lines
would manufacture a delta unrelated to the edit under test.

Four cases are deliberately synthetic, built by mutating a real projection
struct, and each says so at its own site: an admitted export takes its input
by `own`, so every projection reachable from source today declares the
resource; no record is reachable without being referenced; only one projection
schema exists; and no admitted signature reaches 512 records. Building those by
hand is the only way to prove those classifications are live rather than dead
code.

## Validation against a real Component Model toolchain

Implementation:
[`src/public_generic_abi/wit_projection/toolchain_tests.rs`](../src/public_generic_abi/wit_projection/toolchain_tests.rs).

Every other test in this tree checks the emitted WIT against this
repository's *own* bounded parser, which is exactly as wrong as the renderer
whenever both share a misreading of the WIT grammar. These tests hand the
emitted bytes to `wasm-tools` and let it judge.

They are `#[ignore]`d and read an explicitly provisioned
`SEMAPRAX_WIT_WASM_TOOLS` path, following the convention
`assurance_manifest::smt_discharge::tests` already uses for a provisioned
`z3`. An unset variable is a **panic**, never a silent skip: an ignored test
that quietly returns `Ok` when the tool is absent is a false pass, and
reporting "validated" on that basis would be a nonclaim violation.

```sh
SEMAPRAX_WIT_WASM_TOOLS=/opt/homebrew/bin/wasm-tools \
  cargo test --locked -p semaprax --lib \
  public_generic_abi::wit_projection::toolchain_tests -- --ignored
```

Three tests:

1. the projected world is accepted by `wasm-tools component wit`, for a
   nested-record world with a shared `resource` and for a flat world that
   emits every primitive row of the mapping table;
2. deliberately broken WIT — a field naming an undeclared type, and an
   unbalanced brace — is **rejected** by the same command. Without this
   negative control the first test would pass against a stub, a wrong
   subcommand, or a tool that only checks the file exists;
3. the toolchain's own canonical re-rendering stays valid WIT **and** is still
   refused by this profile's decoder with `SPX-PGWIT105`.

### The interop boundary this projection has

`wasm-tools` re-renders WIT in its own canonical form: `own<T>` is printed
bare (in WIT a resource-typed field is owned by default, so this is a notation
difference, not a semantic one) and blank lines are inserted between
declarations. That text is still valid WIT, and `parse_wit_projection` still
refuses it, because that function is a strict canonical-form determinism check
— "these bytes are exactly what SEMAPRAX emits" — and not a general WIT
parser. Refusing a re-rendered variant is correct and by design.

The practical consequence is real: **any workflow that passes this WIT through
standard tooling and feeds the result back is refused.** Test 3 asserts both
halves, so neither can change silently.

**Evidence class: local, re-runnable, opt-in.** Validated against
`wasm-tools 1.259.0` on macOS arm64. No hosted run records this. Passing
`wasm-tools component wit` proves the emitted *types* are a well-formed
Component Model world; it does not build, link, instantiate, or execute a
component.

## Nonclaims

This document and its module admit no `.spx` syntax, define no calling
convention, emit no Component Model binary, generate no host or guest
adapter, execute nothing, and grant no filesystem, process, network,
execution, signing, or publication authority. The one process this tree ever
starts is the `#[ignore]`d toolchain test's `wasm-tools` invocation, which
runs only against an operator-supplied absolute path in
`SEMAPRAX_WIT_WASM_TOOLS` and is never reached by a default `cargo test`; no
compiler or generated-code path spawns anything. They do not:

- export a callable WIT function — only the record/resource *type* shapes an
  eventual function signature would use;
- lower anything to Core Wasm or Component Model bytes;
- prove, or attempt to prove, that a public generic export is "callable
  through a real Wasm component" (issue #176's first acceptance criterion) —
  that requires a calling convention and a physical adapter, both blocked on
  PG-9's undecided support/publication decision and on #229's open compiled
  `.wasm` provider gap;
- widen the milestone's standing support decision, reinterpret any existing
  descriptor/carrier/package/prelude/graph/cleanup schema, or change the
  frozen `semaprax:project-scalar@1.0.0` WIT identity
  [Public Scalar WIT Interface v1](PUBLIC-SCALAR-WIT-INTERFACE-V1.md) owns —
  this projection's package (`semaprax:public-generic-types@0.1.0`), interface
  (`types`), and world (`public-generic-types-v1`) are a distinct, new
  identity precisely so neither can be confused with the other;
- cover a variant, an authored resource, an owned/borrowed string, `Option`,
  or `Result` — the grammar does not admit any of them yet, so none can reach
  this module; each stays a grammar/classifier-level refusal with its own
  existing closed reason until a future grammar version admits it and this
  projection gains its own new, separately gated mapping row.
