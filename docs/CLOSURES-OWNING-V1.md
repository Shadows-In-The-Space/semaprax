# Bounded Owning-Capture Closures v1

Status: reviewed bounded design, past its review checkpoint for the
interpreter. **The interpreter executes this profile end to end; native
C11 and Core Wasm still refuse it.** `hir::resolve` itself keeps refusing
`own fn(...)` with the same stable diagnostic as before (see
[Review checkpoint](#review-checkpoint-and-what-remains)) for every direct
caller, which is what native and Wasm codegen use; only
`interpreter::interpret` substitutes the bounded construction-plus-its-one-
call with a direct call before resolving, so it alone gets real execution.
See [Execution: the interpreter path](#execution-the-interpreter-path).

Audience: language users, compiler contributors, backend implementers, and
reviewers deciding whether to admit this profile beyond source checking.

This is SPX-AI-021's bounded owning-capture closure slice. It is a
separately versioned and checked profile from
[Scalar Snapshot Closures v1](CLOSURES-V1.md) and
[v2](CLOSURES-V2.md): those profiles capture only Copy scalars and never
admit an owning capture. This profile admits exactly one lexical owned
`Bytes` capture and nothing else; it does not extend, relax, or reinterpret
the scalar-snapshot profiles, which are unchanged (see
[`../src/source_verify/closure.rs`](../src/source_verify/closure.rs)).

## Syntax

```semaprax
module example.owning_closures;
@id("example.checksum") fn checksum(payload: own Bytes) -> i64 {
    42
}
@id("example.main") fn main() -> i64 {
    let payload = bytes_zeroed(4usize);
    let clo = own fn() -> i64 { checksum(payload) };
    clo()
}
```

`own fn() -> R { body }` admits **zero explicit parameters** in this bounded
profile. `body` must be exactly one call transferring exactly one lexical
owned `Bytes` local to an ordinary, monomorphic, one-parameter function
declared `fn target(payload: own Bytes) -> R`, where `R` is the closure's
declared result type. No other body shape is admitted:
[`SPX-T292`](../src/source_verify/owning_closure.rs) rejects anything else,
including a body that inspects the payload directly rather than transferring
it whole to a declared target. This is deliberately the smallest useful
shape: a real named function that does the work, invoked once through a
value that carries its one owned argument along with it. Combining this
profile's owning capture with the Copy-scalar captures the existing profiles
already admit is not supported in this slice (a stated limitation, not an
oversight): a follow-up would need `capture_names_scoped` and this module's
admission to cooperate, which this bounded slice does not attempt.

## One-shot semantics, entirely through existing ownership machinery

This profile introduces no new runtime carrier, no new `Type` variant, and no
new `ExprKind` variant. `ExprKind::Closure` gained one field, `owning: bool`
(`false` for every existing scalar-snapshot closure literal, unchanged); see
[`../src/ast.rs`](../src/ast.rs). Everything else is checked by reusing the
same move/availability lattice (`Availability::Moved`, diagnostic
`SPX-O101`) that already governs every other owned value in this language:

- **Construction moves the capture exactly once.** `own fn() -> R { target(payload) }`
  checks that `payload` is an available, unborrowed, owned `Bytes` local
  matching `target`'s one declared parameter, then marks `payload` moved --
  identical to passing it by value into an ordinary call. Reusing `payload`
  afterward reports the same `SPX-O101` "use of resource after ownership was
  moved" any other double-moved value reports.
- **The constructed value's checked type is a reserved, unspellable
  sentinel** (`\0owning-closure.v1`, carrying the target function's name and
  the declared result type as nested pseudo-arguments; see
  `owning_closure::sentinel_type` in
  [`../src/source_verify/owning_closure.rs`](../src/source_verify/owning_closure.rs)).
  No authored identifier can begin with `NUL`, so no function parameter,
  record field, or return-type annotation can ever spell this type. That is
  what keeps a constructed value from escaping through any boundary other
  than the one call this module recognizes: reading it as a plain value
  anywhere else -- aliasing it into another `let`, passing it as an
  argument, returning it, storing it in a field, comparing it -- reduces to
  exactly one check (`owning_closure::reject_escaping_read`, wired into the
  same `Var`-expression handling every other read goes through) because the
  callee of a call expression is never itself a `Var` node.
- **Calling it consumes it.** `clo()` looks up `clo`'s checked type; when it
  is the sentinel, the call is checked directly (zero explicit arguments,
  `SPX-T295` otherwise) without falling through to ordinary named-function or
  bound-value dispatch. A first call on an `Available` binding succeeds and
  marks it moved; a second call sees `Moved` and reports the same `SPX-O101`
  a second use of any other owned value would. **This is what makes the
  second call a compile-time diagnostic rather than a runtime accident**: no
  backend ever decides this, because no backend ever receives a
  double-invocation program in the first place (see the refusal below).
- **Dropping it uncalled needs no new mechanism.** This language already
  drops an unused owned local at scope exit without requiring it be
  consumed; an owning closure that is constructed and never called settles
  through exactly that existing path. There is no "must be called" check to
  add, and none is added.
- **Sticky failure and left-to-right staging are inherited, not
  reimplemented.** Because invocation is checked as an ordinary call to
  `target` with `payload` as its one owned argument, this profile makes no
  independent claim about argument staging or failure propagation; it relies
  entirely on the existing call machinery's guarantees for that call.

## Review checkpoint and what remains

**This profile is checked and negative-tested at the source level.**
[`hir::resolve`](../src/hir/closure/resolve.rs) still refuses every program
containing `own fn(...)` with the same stable diagnostic
(`SPX-H006`, message containing "owning-capture closures" and "not yet
lowered") before any lowering happens, for every *direct* caller of
`hir::resolve` -- which includes `codegen::emit_c` (native C11) and
`wasm::emit_module` (Core Wasm). Neither backend was changed by the
interpreter work below, and neither needed to be: both keep resolving the
original, unmodified program and are refused exactly as before.

**Why the profile stopped at source checking for native/Wasm rather than
lowering further:** giving this closure literal a genuine owning runtime
environment inside shared HIR (rather than treating its checked identity as
sentinel bookkeeping local to `source_verify`) is the seam this document
originally existed to name precisely. Two designs were evaluated and
rejected:

1. **A new `ExprKind`/`Type`/`ResolvedType` variant carrying real owning
   semantics through HIR.** `ExprKind` alone is matched exhaustively in over
   two dozen files, several of them (`src/project/candidate/*`,
   `src/assurance_manifest/smt_discharge/*`) leased to other concurrent
   workers and off-limits to this change. A `Type`/`ResolvedType` variant is
   worse: those enums are matched in well over a hundred sites across
   native/Wasm codegen, cache/graph codecs, and public ABI surfaces. Either
   change ripples far outside a "closure module."
2. **A lexically-scoped construction-to-call association threaded through
   HIR's iterative statement/expression resolver**, so `own fn` sugar could
   desugar directly into an ordinary call at the one call site a `let`
   permits. This requires either widening the shared per-function `Binding`
   type (constructed at roughly sixty sites across HIR resolution) or
   special-casing block resolution inside the single large iterative HIR
   expression resolver every other language feature also depends on. Both
   carry real risk of destabilizing unrelated resolution paths.

Both designs above touch shared HIR machinery consumed by every backend at
once, which is exactly why they were deferred pending review. Once approved
to proceed for the **interpreter only**, a third, smaller path became
available that neither design needed: since `own fn() -> R { target(payload)
}` is checked (by `source_verify::owning_closure`) to carry no state beyond
"which target" and "which captured local," and its only admitted use is one
direct zero-argument call, construction-plus-its-one-call is a pure
*source-text* substitution -- replace the one `name()` call site with the
target call, drop the now-dead `let name = own fn ...` binding -- with no
new runtime carrier, no HIR variant, and no shared-resolver change at all.
[`hir::closure::desugar_owning_closures`](../src/hir/closure/owning_desugar.rs)
performs exactly that rewrite on an already-verified `Program`, and only
`interpreter::interpret` calls it, before its own `hir::resolve`. Every
other caller -- native, Wasm, and `hir::resolve` itself when called
directly -- never sees the rewrite and keeps refusing the original program.

This document, the sentinel encoding, the negative-test corpus in
[`../tests/language/function_values/owning_closures.rs`](../tests/language/function_values/owning_closures.rs),
and that same file's `backend_execution` module (the interpreter-execution
and native/Wasm-refusal evidence) are the record of that reviewed step.

## Execution: the interpreter path

`interpreter::interpret` substitutes before resolving, so HIR never lowers
an owning closure at all -- there is nothing to lower, because the
construction and its one call have already become an ordinary direct call
by the time `hir::resolve` runs. Concretely, for
`let clo = own fn() -> R { target(payload) }; clo()`:

- **Called.** The rewrite produces `target(payload)` where `clo()` stood.
  `payload` is transferred into the call's one argument slot exactly once
  and committed by exactly one `CallCommit`; no exit ever also finalizes
  (drops) it, so a captured owner is never doubly settled.
- **Dropped uncalled.** The rewrite removes the dead `let clo = ...`
  binding entirely and leaves `payload` an ordinary, never-moved owned
  local. It settles through the language's existing scope-exit drop --
  exactly one `FinalizeAction`, freeing it once, with no closure-specific
  mechanism involved.

Both shapes are proven directly against the built `cleanup_plan::CleanupPlan`
in [`hir::closure::owning_desugar`'s tests](../src/hir/closure/owning_desugar/tests.rs),
so "cleaned up exactly once" is checked against the same canonical,
deterministic cleanup-plan structure every other owned value in this
language is checked against -- not a parallel, closure-specific claim.

## What is proven today

- Construction moves its capture exactly once; reuse is `SPX-O101`.
- A first call succeeds cleanly; a second reports `SPX-O101` at the second
  call specifically (isolated by a clean one-call baseline in the same
  test).
- An uncalled closure reports no diagnostics (settles via ordinary scope-exit
  drop).
- Aliasing (`let other = clo;`), passing as an argument, and any other
  escaping read are rejected (`SPX-T296`).
- A malformed body, an undeclared or mis-signatured target, and a non-`Bytes`
  or already-borrowed capture are rejected (`SPX-T292`, `SPX-T293`,
  `SPX-T294`) before any of the above matters.
- Owning closures are refused inside generic functions (`SPX-T291`) and in
  contract expressions (`SPX-O119`).
- Canonical formatting round-trips the authored `own fn` syntax exactly.
- The interpreter executes both the called and the uncalled shape end to
  end and returns the correct value in each case; native C11 and Core Wasm
  still refuse the profile with the same stable diagnostic.
- The captured owner settles exactly once in both interpreter shapes,
  checked directly against the built cleanup plan (see
  [Execution: the interpreter path](#execution-the-interpreter-path)).
- HIR resolution refuses an otherwise source-clean program with the stable
  message above.

## What is not proven, and is not claimed

- No native C11 or Core Wasm execution of any kind: both still refuse this
  profile with `SPX-H006`, proven by
  `backend_execution::native_and_wasm_backends_refuse_the_owning_closure_with_the_stable_diagnostic`
  in the test corpus above.
- The interpreter's execution evidence covers exactly the bounded shape this
  document describes (zero explicit parameters, one lexical owned `Bytes`
  capture, a body that is exactly one transferring call); it makes no claim
  about any broader owning-capture shape.
- No combination with the existing Copy-scalar capture profiles.
- No explicit closure parameters (the profile is fixed at zero).
- No nested owning captures, no capture of a borrowed view, and no public
  callable ABI -- all excluded by construction (the sentinel type cannot be
  spelled in a public signature).
