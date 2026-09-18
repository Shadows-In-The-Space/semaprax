# Lean obligation export v1

Audience: compiler contributors and proof-tooling authors.

Status: one tranche of [issue #186]. Owns three wire identities:

| Identity | Produced by | Consumed by |
| --- | --- | --- |
| `semaprax.lean-obligation-export.v1` | `proof_export::lean::export_module` | a pinned Lean 4 toolchain |
| `semaprax.lean-export-coverage.v1` | `proof_export::certificate::render_coverage` | a reader asking what was *not* covered |
| `semaprax.lean-proof-certificate.v1` | `proof_export::export_obligation_certificate` | `proof_export::verify::*` and any independent replayer |

Implementation: `src/proof_export/`. Specification precedence: this document
owns the profile, the translation, the trusted base, the result grammar and
the certificate schema. Where it and the code disagree, the code's tests
(`src/proof_export/tests.rs`) are the tiebreaker to be fixed, not ignored.

## What has and has not been executed

**No Lean toolchain has ever been run against this export.** `lean`, `lake`
and `elan` are absent from the machine this tranche was written on. Every
test replays recorded kernel output through a fixture implementation of the
[`LeanKernel`](#running-the-kernel) capability. Therefore:

- Deterministic rendering, total coverage accounting, refusal of every
  non-proof output shape, and fail-closed certificate replay are **local
  test evidence**, verified by running them.
- Whether Lean 4 actually accepts the generated proofs is **not evidenced at
  all**. The `omega` tactic each theorem carries is a commitment, not a
  result: if it fails, `lake build` fails, the parser reports
  `build_error`, and no certificate is produced.

Nothing in this document, the generated Lean, or a certificate may be
described as hosted, production, or physical-device evidence.

## Relationship to what already existed

This is not a second proof pipeline. It reuses, rather than restates:

- the bounded-subset vocabulary of
  [`assurance_manifest::smt_discharge`](SMT-DISCHARGE-V1.md) —
  `UnsupportedReason`, `Sort`, `NumericMode` and its checked-range facts;
- `smt_discharge::postcondition_obligation_id` for postcondition identity,
  so one obligation has one id whichever method addresses it;
- `assurance_manifest::proof_certificate::ExternalKernelCapability`, the
  seam that module introduced for this issue, together with its
  "binding checks first, capability second" ordering guarantee;
- the Lean pin of `proofs/kernel0-lean/lean-toolchain`
  (`leanprover/lean4:v4.34.0`, issue #188). A test fails if this export's
  `PINNED_TOOLCHAIN` constant ever diverges from that file.

One piece is restated rather than reused: `subset::sort_of_type` is private
to `smt_discharge`, so `profile::sort_of_type` repeats its five-line type
mapping. The *types* are still the shared ones.

## The profile

`semaprax-lean-export-profile-v1` is a strict narrowing of the bounded
SMT-discharge subset. A declaration is admitted **wholesale or not at all**;
there is no partial translation, so an un-translated construct can never sit
silently inside an exported theorem.

Admitted:

- `fn` declarations with no type parameters, no declared effects, and every
  parameter by value;
- parameter, `let` and return types drawn from `{i64, i32, u8, usize}`;
- at least one `ensures` clause;
- expressions: integer and boolean literals, variables, `result` inside
  `ensures`, unary `-`/`!`, binary `+`/`-`/`*`, the six numeric
  comparisons, `&&`/`||`, block expressions whose statements are all
  immutable `let`.

Refused, each with its own closed reason code:

| Code | Construct |
| --- | --- |
| `generic_function` | `fn f<T>(..)` |
| `effectful_function` | any declared effect |
| `ownership_param_mode` | an `own`/`borrow`/`shared` parameter |
| `bool_valued_position` | `bool` as a parameter, `let`, or return type |
| `conditional_expression` | `if` |
| `expr` | calls, division/remainder, floats, strings, aggregates, `match`, `try`, projection, closures |
| `non_let_statement` | assignment, `unsafe`, `while`, `for` |
| `mutable_local_binding` | `let mut` |
| `operand_sort`, `operand_type_mismatch`, `type_mismatch` | operand sorts that disagree |
| `unknown_name` | an unresolved variable |
| `no_ensures_clause`, `no_contract_clauses` | nothing to export |
| `unsupported_value_type` | a type outside the five scalars |
| `non_function_declaration` | records, variants, classes, resources, interfaces, protocols, implementations, agents |

`bool` is excluded as a *value* because contract clauses translate to Lean
`Prop`s; admitting a `bool` value would need a `Bool`/`Prop` coercion this
profile does not introduce. `if` is excluded because `ite` in every goal
takes the emitted proof past the linear-arithmetic tactic budget — deferred
rather than emitted unproved.

## The translation, and why the model is faithful

Every admitted scalar becomes Lean's unbounded `Int`. On its own that would
be **unfaithful**: SEMAPRAX arithmetic is checked (trapping, never
wrapping), so `a + b` at `i64` is not mathematical addition.

The gap is closed exactly the way `smt_discharge` closes it for SMT:

- A **parameter's** declared range is a *hypothesis*
  (`h_lo_i : min ≤ v`, `h_hi_i : v ≤ max`).
- An **arithmetic node's** range is an *obligation*: a separate theorem
  `min ≤ term ∧ term ≤ max`.

These two shapes are deliberately not interchangeable. Giving a computed
term the unconditional range hypothesis a parameter gets is issue #184's
worst bug (it made a genuine overflow vacuously provable), and
`a_parameter_range_is_a_hypothesis_and_an_arithmetic_range_is_a_goal` pins
the distinction.

A postcondition is claimed only when every range obligation of the same
declaration was kernel-checked in the same run. Under that conjunction the
`Int` term and the runtime value coincide on every input satisfying the
hypotheses, so proving the postcondition over `Int` proves it for the
trapping semantics. `verify_certificate` re-checks this from the
certificate alone: an obligation belonging to the certified declaration that
carries no kernel axiom set is a rejection.

Hypothesis scoping follows evaluation order. Binders are appended as the
walk proceeds (parameters, parameter ranges, `requires_0..n`, each `let`
definition, `result`), and each obligation records how many binders were in
scope when it was discovered. A range obligation arising inside
`requires[1]` therefore may assume `requires[0]` but not `requires[2]`,
`result`, or any later `let`.

### Names

A theorem name is `spx_<escape(stable_id)>_<kind>_<index>` inside the fixed
namespace `SemapraxExport`. `escape` keeps ASCII alphanumerics and rewrites
every other byte as `_` plus two lowercase hex digits — including `_`
itself, which makes the encoding prefix-free and therefore injective. Two
distinct stable ids can never collide on one theorem name, which is the
issue's named "name sanitization can collide and misassociate declarations"
failure mode.

Local binders are `v_<escape(name)>` for parameters and
`v_<escape(name)>_<n>` for `let` bindings (the counter makes shadowing
harmless); hypotheses are positional (`h_lo_i`, `h_hi_i`, `h_req_i`,
`h_def_n`, `h_result`), so no source identifier can collide with one.

### Determinism

The rendered bytes are a pure function of the parsed program: source order
everywhere, no map iteration, no timestamps, and **no host path** — the
header carries the module name and semantic revision only, so two checkouts
render identical bytes. Rendering uses plain `format!`, not the budgeted
formatter, because these bytes are bound by digest and a silent truncation
under an ambient output budget would be a determinism bug.

`src/proof_export/testdata/shifted.lean.golden` pins the output for one
fixture module. Re-pin it deliberately with
`cargo test -p semaprax --lib rewrite_the_pinned_lean_golden -- --ignored`
and review the diff.

## Trusted base and assumptions

Eight entries, defined once in `lean::ASSUMPTIONS` and reproduced verbatim
in the generated Lean header, the coverage report, and every certificate:

| Id | Assumption |
| --- | --- |
| `A1-int-model` | scalars modeled as Lean `Int` with range hypotheses; faithful only with A2 |
| `A2-range-obligations-required` | a postcondition counts only when every range obligation of the same function was checked in the same file |
| `A3-requires-assumed` | `requires` clauses are assumed, never proved; nothing is claimed about callers |
| `A4-lean-standard-axioms` | `propext`, `Classical.choice`, `Quot.sound` trusted; anything else, `sorryAx` above all, invalidates |
| `A5-lean-kernel-tcb` | the pinned Lean toolchain and its kernel are trusted, not verified |
| `A6-translation-tcb` | this Rust translation is trusted and unverified; a translation bug is invisible to the Lean kernel |
| `A7-purity` | the profile is pure, total and effect-free, so evaluation order is unobservable and unmodeled |
| `A8-no-lowering-claim` | nothing claims the backend lowering preserves a proved source theorem |

## Running the kernel

Running Lean is the `proof_export::LeanKernel` capability, supplied by the
caller:

```rust
pub struct KernelRun { pub toolchain: String, pub output: String }
pub trait LeanKernel {
    fn check(&self, lean_source: &str) -> Result<KernelRun, Diagnostic>;
}
```

**No implementation ships in this crate.** The compiler gains no ambient
process or filesystem authority because a proof export exists, and an
implementation that was never executed here could not be honestly tested.

## Result grammar

`kernel_report::parse(expected, toolchain, output)` is a pure function to a
closed verdict. It is fail-closed by construction: it starts from rejected
and reaches `Checked` only when every expected theorem produced exactly one
`#print axioms` line whose axiom set is a subset of the three standard
axioms.

Refusals, in evaluation order:

| Code | Trigger |
| --- | --- |
| `toolchain_drift` | the reported toolchain is not `leanprover/lean4:v4.34.0` |
| `timeout` | `(deterministic) timeout`, `maximum recursion depth has been reached`, `deep recursion was detected` |
| `admitted_hole` | `declaration uses 'sorry'`, `uses sorry`, or `sorryAx` anywhere in the output |
| `build_error` | any line containing `error:` |
| `unrecognized_output` | no `#print axioms` line at all |
| `missing_theorem` | an expected theorem has no line |
| `duplicate_theorem` | an expected theorem has more than one line |
| `forbidden_axiom` | any axiom outside the standard three |

A timeout, a build error and an admitted hole are refusals, not weaker
forms of success. This mirrors what `scripts/kernel0-lean-gate.py` already
does for the Kernel-0 proof: the elaborated proof term's axiom set, not a
source-text scan, is authoritative.

## Certificate schema

`semaprax.lean-proof-certificate.v1`, an outer
`{schema, digest, bytes, payload}` envelope with its own domain-separated
SHA-256 for each digest kind
(`semaprax.lean-proof-certificate.{source,payload,lean,artifact}.v1\0`).

Payload keys, all required and exact:

`schema`, `export_schema`, `source{path,revision,sha256}`, `module`,
`declaration_id`, `obligation_id`, `ensures_index`, `theorem_name`,
`profile`, `compiler_version`, `kernel{identity,toolchain,standard_axioms}`,
`artifact{target,bytes,sha256}`, `lean_source`, `lean_source_sha256`,
`obligations[]`, `assumptions[]`, `unsupported[]`, `verdict`, `nonclaims[]`.

`verdict` admits exactly one value, `kernel_checked`. The whole generated
Lean document is embedded verbatim, so a third party can hand it to their
own Lean toolchain without trusting this exporter; `unsupported[]` travels
with the claim so a reader is always told what the export refused.

### Replay, fail-closed

1. `verify_certificate` — filesystem-free. Recomputes the envelope digest
   over the exact payload bytes, requires closed key sets and vocabularies,
   recomputes the embedded Lean document's digest, and rejects any recorded
   axiom outside the standard three. A certificate recording `sorryAx` dies
   here with no toolchain and no source in sight.
2. `verify_certificate_against_source` — additionally re-reads the source,
   re-parses and re-verifies it, re-derives the semantic revision,
   **re-renders the Lean document from scratch and requires byte
   equality**, checks the compiler identity, and recompiles the bound Wasm
   core module requiring digest equality. Re-rendering rather than trusting
   the embedded bytes is the point: a hand-edited document that weakens a
   theorem or drops an obligation no longer equals what the translator
   deterministically produces, so it is refused even though its recorded
   verdict still reads `kernel_checked`.
3. `verify_certificate_against_artifact` — compiler-free and
   filesystem-free: confirms artifact bytes a caller already holds are the
   bound ones, saying nothing about where they came from.
4. `verify_certificate_with_capability` — bindings first, then the supplied
   `ExternalKernelCapability`. A capability that always confirms can never
   widen what the binding layer already refused.

Diagnostics: `SPX-Z110` nothing to certify, `SPX-Z111` certificate
inconsistency, `SPX-Z112` drift.

## Non-claims

Recorded in every certificate's `nonclaims`, and binding on any prose
written about this module:

- Kernel-checked status covers only the listed obligations of the listed
  declaration. Declarations under `unsupported` are not proved.
- **No ProgramRoot binding.** A managed-workspace `ProgramRoot` derives from
  a `SemanticWorkspaceRevision`; this export binds a single source file's
  semantic revision instead, exactly as the shipped SMT certificate does.
  That is a narrower binding.
- Artifact binding covers only the `wasm-core-module-v1` target. No native
  artifact is bound: native codegen emits C11 source text needing an
  external, unpinned C toolchain this crate does not invoke.
- Artifact binding does not by itself prove the backend lowering preserves
  the source theorem.
- The SEMAPRAX-to-Lean translation is trusted and unverified.
- `requires` clauses are assumed, not proved.
- No target execution, no project test discovery, no source writes.
- Not merged into the Assurance Manifest obligation lattice. A certificate
  is proof data, not authority: it grants no execution, publication,
  signing, or merge permission.

## Not done in this tranche

- No Lean toolchain execution, and therefore no evidence that any generated
  proof is accepted.
- No `LeanKernel` implementation (no `lake build` runner).
- No CLI surface; the module is library-only.
- No Assurance Manifest merge, and no `ObligationKind` for checked-range
  obligations — they carry their own
  `semaprax.lean-export.range.v1:...` ids precisely so they are not
  mistaken for manifest obligations.
- No mutation ladder over *target* changes (only source, revision,
  compiler, Lean document, and artifact are exercised).
- `if`, division/remainder, `bool` values, records and calls remain outside
  the profile.

[issue #186]: https://github.com/wsdt/semaprax/issues/186
