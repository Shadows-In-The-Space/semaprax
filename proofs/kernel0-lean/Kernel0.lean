/-
Kernel-0 mechanization spike (SEMAPRAX docs/SEMANTIC-KERNEL-V1.md).

This is a spike, not a complete mechanization of Kernel-0. See
docs/KERNEL-PROOF-MECHANIZATION-V1.md for the full writeup: what this file
covers, what it deliberately leaves out, and what it does and does not tell
you about the real compiler. In one paragraph:

This file mechanizes Kernel-0's full term/type syntax (scalars,
unary/binary operators, `if`, `let`, non-recursive `call`, using de Bruijn
indices so substitution needs no capture-avoidance machinery), its static
typing judgment `HasType`, and its small-step, left-to-right, call-by-value
operational semantics `Step`. Unlike the source document, arithmetic here is
modeled as genuinely **partial**: `evalArith`/`evalNeg` return `none` for
division/remainder by zero and for `i64` range overflow, and `Step` has no
rule to fire when they do. `FaultRedex` names exactly those stuck-but-
intended points, so **Progress** is stated and fully proved as a real
trichotomy -- value, steps, or `FaultRedex` -- for the scalar-and-`if`
sub-fragment (`ScalarIf`), matching the eight-outcome `Fault` finding
`docs/SEMANTIC-KERNEL-V1.md`'s differential test made about the *document's*
two-outcome statement. **Preservation** is stated and fully proved for the
*entire* language, `Let` and non-recursive `Call` included, with **zero**
`sorry`/`admit`/`axiom` beyond Lean's own standard three (see
`#print axioms` invocations at the bottom and
docs/KERNEL-PROOF-MECHANIZATION-V1.md's verbatim `lake build` transcript).

Mechanizing `Call`'s Preservation case surfaced a second real gap, this time
in the *encoding* rather than the document: the source document's own `call`
typing rule (and this file's first attempt at it) checks a call's arguments
against the callee's declared signature but never requires the callee's own
*body* to type-check against that signature. That is a background invariant
every real top-level `Fn` satisfies once, when it is itself resolved --
never restated at each call site -- and both the source document's paper
rule and a first Lean encoding of it can silently omit naming it, leaving
Preservation's `Call`-substitution case with no hypothesis to substitute
into (a real, provable-only-with-more-information gap, not a proof-tactic
gap -- seen firsthand: an earlier, discarded scratch attempt at this same
proof left exactly this case as `sorry` for exactly this reason).
`WellFormedProgram` below names the missing invariant explicitly, threaded
through `preservation` as a hypothesis, closing the gap honestly rather than
by construction-order coincidence.

Issue #188's seeded-defect audit of this file (proving the mechanized proof
can actually reject an injected unsoundness, not only that it currently
passes) surfaced a third real gap while choosing which real-system boundary
to probe: `evalArith`'s `mod` case originally had no `i64::MIN`/`-1`
exclusion, unlike `div`. Mathematically the remainder is always
representable, so this was not a typo relative to the file's own "range
overflow" framing -- but the real system faults there anyway
(`i64::MIN % -1` traps on real hardware/Rust the same one shared `idiv`
instruction that makes `i64::MIN / -1` trap, confirmed against this repo's
own `src/kernel_zero/eval.rs::checked_rem` and an already-passing
differential-corpus case), so the old clause was a genuine, until-now-
unnoticed fidelity gap against Kernel-0's real fault set -- not merely
against the source document. Fixed by naming the same `i64::MIN`/`-1` pair
explicitly for `mod` too (see `evalArith`'s own doc comment); Progress and
Preservation needed no proof changes at all to accept the fix, since neither
theorem inspects `evalArith`'s formula, only its `Option` shape -- exactly
why no existing proof obligation had ever surfaced this gap on its own.
-/

namespace Kernel0

/-! ## Syntax -/

/-- Kernel-0's two scalar types. -/
inductive Ty where
  | int
  | bool
deriving DecidableEq, Repr

/-- The five arithmetic binary operators. -/
inductive ArithOp where
  | add | sub | mul | div | mod
deriving DecidableEq, Repr

/-- The six comparison operators. `eq`/`ne` apply to both Kernel-0 scalar
types; ordering remains an `Int`-only operation. -/
inductive CmpOp where
  | eq | ne | lt | le | gt | ge
deriving DecidableEq, Repr

/-- Kernel-0 expressions, using de Bruijn indices for `Var`/`Let` binding and
a flat function-table index for `Call`. `And`/`Or` are separated from the
generic `Arith`/`Cmp` binary operators because their reduction rule is
short-circuiting (RFC 0001's "lazy boolean operands execute only when
required"), not the generic left-to-right-then-combine shape the other
binary operators share. -/
inductive Expr where
  | intLit (n : Int)
  | boolLit (b : Bool)
  | var (i : Nat)
  | arith (op : ArithOp) (e1 e2 : Expr)
  | cmp (op : CmpOp) (e1 e2 : Expr)
  | neg (e : Expr)
  | not (e : Expr)
  | and (e1 e2 : Expr)
  | or (e1 e2 : Expr)
  | ite (c e1 e2 : Expr)
  | letIn (e1 e2 : Expr)
  | call (f : Nat) (args : List Expr)
deriving Repr

/-- A single top-level `Fn`: parameter types (the body's de Bruijn context,
index 0 = the first parameter), a return type, and a body. -/
structure FunDef where
  params : List Ty
  ret : Ty
  body : Expr
deriving Repr

/-- A whole Kernel-0 program: a fixed, indexed table of `Fn`s. This
mechanization does not model or use the call graph's acyclicity (Kernel-0's
termination argument); see docs/KERNEL-PROOF-MECHANIZATION-V1.md's scope
note. -/
abbrev Program := List FunDef

/-! ## Values -/

/-- `v ::= n | true | false` from the source document. -/
inductive IsValue : Expr → Prop where
  | intLit (n : Int) : IsValue (.intLit n)
  | boolLit (b : Bool) : IsValue (.boolLit b)

/-! ## Partial `i64` arithmetic: the `Fault` outcome

The source document states one total-looking reduction rule, `n1 op n2 = n
("ordinary arithmetic")`, with no side condition. Real `i64` arithmetic is
partial: zero divisor and range overflow have no answer. `evalArith` and
`evalNeg` return `none` exactly there, and `Step` below has **no rule** that
fires on `none` -- this is the mechanized form of the exact gap
`docs/SEMANTIC-KERNEL-V1.md`'s differential test found by trying to write a
reference evaluator directly against the document's stated rule. -/

/-- `i64::MIN`. -/
def i64Min : Int := -(2 ^ 63)

/-- `i64::MAX`. -/
def i64Max : Int := 2 ^ 63 - 1

/-- Ordinary `i64` arithmetic, made explicitly partial: `none` for a zero
divisor (`div`/`mod`) or a result outside `i64`'s representable range
(covers `add`/`sub`/`mul` overflow, and `i64::MIN / -1` for `div`). `mod`
needs a *separate* explicit exclusion for the same `i64::MIN`/`-1` pair,
found and fixed by issue #188's seeded-defect audit of this file: unlike
`div`'s quotient (`2^63`, out of `i64` range -- `inRange` already rejects
it with no special case needed), the mathematical remainder of any integer
division is always representable (`|a % b| < |b| ≤ i64Max`), so `inRange`
never rejects it and a naive `some (a % b)` here is a real, silent fidelity
gap against the actual system: `i64::MIN % -1` faults as `RemainderOverflow`
on real hardware/Rust (`checked_rem`'s documented `Self::MIN`/`-1` special
case, mirroring `checked_div`'s trap on the same one shared `idiv`
instruction, not a range check) and in this repo's own reference
evaluator/compiler (`src/kernel_zero/eval.rs`'s `checked_rem`, exercised
by an already-passing differential-corpus case,
`src/kernel_zero/differential.rs`'s `(-9223372036854775807 - 1) % -1`).
Confirmed empirically before this fix: `#eval (i64Min % (-1 : Int))`
reduces to `0`, which is in `i64` range, so the old `some (a % b)` clause
made this term step to `0` (a value) instead of naming it a `FaultRedex` --
Progress/Preservation both stayed provable regardless (neither theorem
inspects `evalArith`'s formula, only its `Option` shape), so no proof
obligation ever surfaced this; only comparing this file's modeled fault set
against the real system's did. -/
def evalArith (op : ArithOp) (a b : Int) : Option Int :=
  let inRange (r : Int) : Option Int := if i64Min ≤ r ∧ r ≤ i64Max then some r else none
  let divRemOverflows : Bool := a = i64Min ∧ b = -1
  match op with
  | .add => inRange (a + b)
  | .sub => inRange (a - b)
  | .mul => inRange (a * b)
  | .div => if b = 0 then none else inRange (a / b)
  | .mod => if b = 0 then none else if divRemOverflows then none else some (a % b)

/-- Unary negation, partial at `i64::MIN` (`-i64::MIN` is not representable). -/
def evalNeg (n : Int) : Option Int :=
  if n = i64Min then none else some (-n)

/-- Whether a comparison operator is admitted for boolean operands. The real
Kernel-0 predicate admits only boolean equality/inequality -- not ordering --
so this side condition keeps the mechanized calculus aligned with that
boundary rather than making every `CmpOp` polymorphic by accident. -/
def BoolEquality : CmpOp → Prop
  | .eq | .ne => True
  | .lt | .le | .gt | .ge => False

/-- The six comparison operators on `Int`; total (no overflow case). -/
def evalCmp : CmpOp → Int → Int → Bool
  | .eq, a, b => decide (a = b)
  | .ne, a, b => decide (a ≠ b)
  | .lt, a, b => decide (a < b)
  | .le, a, b => decide (a ≤ b)
  | .gt, a, b => decide (a > b)
  | .ge, a, b => decide (a ≥ b)

/-- The two comparison operators admitted for `Bool`; total by construction.
The impossible ordering cases return `false` only to keep this evaluator
total -- [`HasType.cmpBool`] and [`Step.cmpBoolVal`] both require
[`BoolEquality`], so no well-typed term can observe those branches. -/
def evalBoolCmp : CmpOp → Bool → Bool → Bool
  | .eq, a, b => decide (a = b)
  | .ne, a, b => decide (a ≠ b)
  | .lt, _, _ | .le, _, _ | .gt, _, _ | .ge, _, _ => false

/-! ## Static typing -/

mutual
  /-- `Γ ⊢ e : T`, relative to a fixed function table `P`. -/
  inductive HasType : Program → List Ty → Expr → Ty → Prop where
    | intLit {P Γ n} : HasType P Γ (.intLit n) .int
    | boolLit {P Γ b} : HasType P Γ (.boolLit b) .bool
    | var {P Γ i T} (h : Γ[i]? = some T) : HasType P Γ (.var i) T
    | arith {P Γ op e1 e2} (h1 : HasType P Γ e1 .int) (h2 : HasType P Γ e2 .int) :
        HasType P Γ (.arith op e1 e2) .int
    | cmpInt {P Γ op e1 e2} (h1 : HasType P Γ e1 .int) (h2 : HasType P Γ e2 .int) :
        HasType P Γ (.cmp op e1 e2) .bool
    | cmpBool {P Γ op e1 e2} (hop : BoolEquality op) (h1 : HasType P Γ e1 .bool)
        (h2 : HasType P Γ e2 .bool) : HasType P Γ (.cmp op e1 e2) .bool
    | neg {P Γ e} (h : HasType P Γ e .int) : HasType P Γ (.neg e) .int
    | not {P Γ e} (h : HasType P Γ e .bool) : HasType P Γ (.not e) .bool
    | and {P Γ e1 e2} (h1 : HasType P Γ e1 .bool) (h2 : HasType P Γ e2 .bool) :
        HasType P Γ (.and e1 e2) .bool
    | or {P Γ e1 e2} (h1 : HasType P Γ e1 .bool) (h2 : HasType P Γ e2 .bool) :
        HasType P Γ (.or e1 e2) .bool
    | ite {P Γ c e1 e2 T} (hc : HasType P Γ c .bool) (h1 : HasType P Γ e1 T)
        (h2 : HasType P Γ e2 T) : HasType P Γ (.ite c e1 e2) T
    | letIn {P Γ e1 e2 T1 T2} (h1 : HasType P Γ e1 T1) (h2 : HasType P (T1 :: Γ) e2 T2) :
        HasType P Γ (.letIn e1 e2) T2
    | call {P Γ f args fd} (hf : P[f]? = some fd) (hargs : ArgsHaveTypes P Γ args fd.params) :
        HasType P Γ (.call f args) fd.ret

  /-- Element-wise typing of a call's argument list against a `Fn`'s declared
  parameter types, in order. -/
  inductive ArgsHaveTypes : Program → List Ty → List Expr → List Ty → Prop where
    | nil {P Γ} : ArgsHaveTypes P Γ [] []
    | cons {P Γ e es T Ts} (h : HasType P Γ e T) (hs : ArgsHaveTypes P Γ es Ts) :
        ArgsHaveTypes P Γ (e :: es) (T :: Ts)
end

/-- The invariant Preservation's `Call` case needs and the source document's
paper `call` rule leaves implicit: every function actually named in `P`
type-checks its own body against its own declared signature. Real compilers
enforce this once, when a `Fn` is resolved, never at each call site;
mechanization is what forces it to be named rather than assumed. -/
def WellFormedProgram (P : Program) : Prop :=
  ∀ (f : Nat) (fd : FunDef), P[f]? = some fd → HasType P fd.params fd.body fd.ret

/-! ## Substitution

Kernel-0 substitutes only *values* (closed literals/booleans, per `IsValue`)
for variables (`let x = v ; e2 -> e2[x := v]`, and a call's beta step
substitutes a whole argument list of values at once). Because a value has no
free de Bruijn variables, substituting it under further binders never needs
to shift the substituted term itself -- only the *body*'s own variable
references need the usual de-Bruijn index bookkeeping. `substEnvAt base env e`
substitutes `env` for the `env.length` variables starting at `base`,
shifting every remaining free variable above that window down by
`env.length`, and leaves every variable below `base` (bound *inside* `e`, by
a binder the recursion has already descended under) untouched. -/

def substEnvAt (base : Nat) (env : List Expr) : Expr → Expr
  | .intLit n => .intLit n
  | .boolLit b => .boolLit b
  | .var i =>
      if i < base then .var i
      else if h : i - base < env.length then env[i - base]'h
      else .var (i - env.length)
  | .arith op e1 e2 => .arith op (substEnvAt base env e1) (substEnvAt base env e2)
  | .cmp op e1 e2 => .cmp op (substEnvAt base env e1) (substEnvAt base env e2)
  | .neg e => .neg (substEnvAt base env e)
  | .not e => .not (substEnvAt base env e)
  | .and e1 e2 => .and (substEnvAt base env e1) (substEnvAt base env e2)
  | .or e1 e2 => .or (substEnvAt base env e1) (substEnvAt base env e2)
  | .ite c e1 e2 => .ite (substEnvAt base env c) (substEnvAt base env e1) (substEnvAt base env e2)
  | .letIn e1 e2 => .letIn (substEnvAt base env e1) (substEnvAt (base + 1) env e2)
  | .call f args => .call f (args.map (substEnvAt base env))

/-- Single-variable substitution is the one-element case of `substEnvAt`. -/
def substAt (base : Nat) (v : Expr) (e : Expr) : Expr := substEnvAt base [v] e

/-! ## Operational semantics -/

/-- Small-step, left-to-right, call-by-value reduction, relative to a fixed
function table `P`. `arithVal`/`negVal` fire only when `evalArith`/`evalNeg`
return `some` -- when they return `none` (zero divisor, overflow), **no
rule fires at all**: this is the mechanized "no stated reduction" gap, not
patched away. `callArgs` steps the first non-value argument of a call. -/
inductive Step (P : Program) : Expr → Expr → Prop where
  | arithStep1 {op e1 e1' e2} (h : Step P e1 e1') : Step P (.arith op e1 e2) (.arith op e1' e2)
  | arithStep2 {op v1 e2 e2'} (h1 : IsValue v1) (h : Step P e2 e2') :
      Step P (.arith op v1 e2) (.arith op v1 e2')
  | arithVal {op a b n} (h : evalArith op a b = some n) :
      Step P (.arith op (.intLit a) (.intLit b)) (.intLit n)
  | cmpStep1 {op e1 e1' e2} (h : Step P e1 e1') : Step P (.cmp op e1 e2) (.cmp op e1' e2)
  | cmpStep2 {op v1 e2 e2'} (h1 : IsValue v1) (h : Step P e2 e2') :
      Step P (.cmp op v1 e2) (.cmp op v1 e2')
  | cmpVal {op a b} : Step P (.cmp op (.intLit a) (.intLit b)) (.boolLit (evalCmp op a b))
  | cmpBoolVal {op a b} (hop : BoolEquality op) :
      Step P (.cmp op (.boolLit a) (.boolLit b)) (.boolLit (evalBoolCmp op a b))
  | negStep {e e'} (h : Step P e e') : Step P (.neg e) (.neg e')
  | negVal {n m} (h : evalNeg n = some m) : Step P (.neg (.intLit n)) (.intLit m)
  | notStep {e e'} (h : Step P e e') : Step P (.not e) (.not e')
  | notVal {b} : Step P (.not (.boolLit b)) (.boolLit (!b))
  | andStep {e1 e1' e2} (h : Step P e1 e1') : Step P (.and e1 e2) (.and e1' e2)
  | andTrue {e2} : Step P (.and (.boolLit true) e2) e2
  | andFalse {e2} : Step P (.and (.boolLit false) e2) (.boolLit false)
  | orStep {e1 e1' e2} (h : Step P e1 e1') : Step P (.or e1 e2) (.or e1' e2)
  | orTrue {e2} : Step P (.or (.boolLit true) e2) (.boolLit true)
  | orFalse {e2} : Step P (.or (.boolLit false) e2) e2
  | iteStep {c c' e1 e2} (h : Step P c c') : Step P (.ite c e1 e2) (.ite c' e1 e2)
  | iteTrue {e1 e2} : Step P (.ite (.boolLit true) e1 e2) e1
  | iteFalse {e1 e2} : Step P (.ite (.boolLit false) e1 e2) e2
  | letStep {e1 e1' e2} (h : Step P e1 e1') : Step P (.letIn e1 e2) (.letIn e1' e2)
  | letBeta {v e2} (h : IsValue v) : Step P (.letIn v e2) (substAt 0 v e2)
  | callArgs {f vs e e' es} (hvs : ∀ v ∈ vs, IsValue v) (h : Step P e e') :
      Step P (.call f (vs ++ e :: es)) (.call f (vs ++ e' :: es))
  | callBeta {f args fd} (hargs : ∀ v ∈ args, IsValue v) (hf : P[f]? = some fd) :
      Step P (.call f args) (substEnvAt 0 args fd.body)

/-- The stuck-but-*intended* points `Step` deliberately has no rule for:
exactly the arithmetic/negation redexes `evalArith`/`evalNeg` refuse, closed
under the same left-to-right congruence contexts `Step` itself uses (a base
`Fault` nested under an outer, otherwise-steppable form is stuck too -- e.g.
`1 + (2 / 0)`: the outer `+` cannot fire until its right operand is a value,
and the right operand is stuck, so the whole term is stuck, not merely its
subterm). This is the third outcome the source document's Progress theorem
needs and does not state -- see `progress_scalarIf` below. Its shape had to
be widened from a first draft's base-case-only version once the Progress
proof for `Expr.arith`/`Expr.cmp` (etc.) with one faulting operand refused
to close: a mechanized reminder that "stuck" is a property of where
evaluation gets to, not only of a term's own top-level shape. -/
inductive FaultRedex : Expr → Prop where
  | arithBase {op a b} (h : evalArith op a b = none) :
      FaultRedex (.arith op (.intLit a) (.intLit b))
  | negBase {n} (h : evalNeg n = none) : FaultRedex (.neg (.intLit n))
  | arithStep1 {op e1 e2} (h : FaultRedex e1) : FaultRedex (.arith op e1 e2)
  | arithStep2 {op v1 e2} (h1 : IsValue v1) (h : FaultRedex e2) : FaultRedex (.arith op v1 e2)
  | cmpStep1 {op e1 e2} (h : FaultRedex e1) : FaultRedex (.cmp op e1 e2)
  | cmpStep2 {op v1 e2} (h1 : IsValue v1) (h : FaultRedex e2) : FaultRedex (.cmp op v1 e2)
  | negStep {e} (h : FaultRedex e) : FaultRedex (.neg e)
  | notStep {e} (h : FaultRedex e) : FaultRedex (.not e)
  | andStep {e1 e2} (h : FaultRedex e1) : FaultRedex (.and e1 e2)
  | orStep {e1 e2} (h : FaultRedex e1) : FaultRedex (.or e1 e2)
  | iteStep {c e1 e2} (h : FaultRedex c) : FaultRedex (.ite c e1 e2)

/-! ## Canonical forms -/

theorem canonical_int {P Γ v} (hv : IsValue v) (ht : HasType P Γ v .int) :
    ∃ n, v = .intLit n := by
  cases hv with
  | intLit n => exact ⟨n, rfl⟩
  | boolLit b => cases ht

theorem canonical_bool {P Γ v} (hv : IsValue v) (ht : HasType P Γ v .bool) :
    ∃ b, v = .boolLit b := by
  cases hv with
  | intLit n => cases ht
  | boolLit b => exact ⟨b, rfl⟩

/-! ## Boolean-comparison boundary

The real Kernel-0 admission predicate permits equality and inequality on
`bool`, but rejects ordering. These two compact boundary theorems make that
alignment executable in the proof artifact itself: extending `CmpOp`,
`HasType`, or the boolean evaluator must preserve both the admitted case and
the refusal case, rather than silently treating every comparison as
polymorphic. They are headline-gated at the bottom of this file alongside
Progress and Preservation. -/

theorem bool_equality_has_type {P Γ a b} :
    HasType P Γ (.cmp .eq (.boolLit a) (.boolLit b)) .bool :=
  HasType.cmpBool True.intro HasType.boolLit HasType.boolLit

theorem bool_equality_steps {P} :
    Step P (.cmp .eq (.boolLit true) (.boolLit false)) (.boolLit false) :=
  Step.cmpBoolVal True.intro

theorem bool_inequality_steps {P} :
    Step P (.cmp .ne (.boolLit true) (.boolLit false)) (.boolLit true) :=
  Step.cmpBoolVal True.intro

theorem bool_ordering_is_not_typed {P Γ a b} :
    ¬ HasType P Γ (.cmp .lt (.boolLit a) (.boolLit b)) .bool := by
  intro h
  cases h with
  | cmpInt h1 _ => cases h1
  | cmpBool hop _ _ => cases hop

/-! ## Progress, for the scalar-and-`if` sub-fragment

`ScalarIf` is literals, unary/binary scalar operators, and `if`, excluding
`Var`/`Let`/`Call` -- every `ScalarIf` term is syntactically closed, so this
proof needs no substitution lemma. Its conclusion is a real **trichotomy**:
value, steps, or `FaultRedex` -- the corrected shape of the source
document's Progress theorem, which states only the first two and so is
incomplete exactly where `FaultRedex` now names the gap precisely. -/
inductive ScalarIf : Expr → Prop where
  | intLit {n} : ScalarIf (.intLit n)
  | boolLit {b} : ScalarIf (.boolLit b)
  | arith {op e1 e2} (h1 : ScalarIf e1) (h2 : ScalarIf e2) : ScalarIf (.arith op e1 e2)
  | cmp {op e1 e2} (h1 : ScalarIf e1) (h2 : ScalarIf e2) : ScalarIf (.cmp op e1 e2)
  | neg {e} (h : ScalarIf e) : ScalarIf (.neg e)
  | not {e} (h : ScalarIf e) : ScalarIf (.not e)
  | and {e1 e2} (h1 : ScalarIf e1) (h2 : ScalarIf e2) : ScalarIf (.and e1 e2)
  | or {e1 e2} (h1 : ScalarIf e1) (h2 : ScalarIf e2) : ScalarIf (.or e1 e2)
  | ite {c e1 e2} (hc : ScalarIf c) (h1 : ScalarIf e1) (h2 : ScalarIf e2) : ScalarIf (.ite c e1 e2)

/-- **Progress, scalar-and-`if` fragment, corrected three-outcome form.**
Every well-typed `ScalarIf` term is a value, can step, or is a
`FaultRedex`. Fully proved, no `sorry`. -/
theorem progress_scalarIf {P Γ e T} (hs : ScalarIf e) (ht : HasType P Γ e T) :
    IsValue e ∨ (∃ e', Step P e e') ∨ FaultRedex e := by
  induction hs generalizing T with
  | intLit => exact Or.inl (.intLit _)
  | boolLit => exact Or.inl (.boolLit _)
  | arith h1 h2 ih1 ih2 =>
      cases ht with
      | arith ht1 ht2 =>
        rcases ih1 ht1 with hv1 | ⟨e1', hstep1⟩ | hf1
        · rcases ih2 ht2 with hv2 | ⟨e2', hstep2⟩ | hf2
          · obtain ⟨a, rfl⟩ := canonical_int hv1 ht1
            obtain ⟨b, rfl⟩ := canonical_int hv2 ht2
            rcases hr : evalArith _ a b with _ | n
            · exact Or.inr (Or.inr (.arithBase hr))
            · exact Or.inr (Or.inl ⟨_, .arithVal hr⟩)
          · exact Or.inr (Or.inl ⟨_, .arithStep2 hv1 hstep2⟩)
          · exact Or.inr (Or.inr (.arithStep2 hv1 hf2))
        · exact Or.inr (Or.inl ⟨_, .arithStep1 hstep1⟩)
        · exact Or.inr (Or.inr (.arithStep1 hf1))
  | cmp h1 h2 ih1 ih2 =>
      cases ht with
      | cmpInt ht1 ht2 =>
        rcases ih1 ht1 with hv1 | ⟨e1', hstep1⟩ | hf1
        · rcases ih2 ht2 with hv2 | ⟨e2', hstep2⟩ | hf2
          · obtain ⟨a, rfl⟩ := canonical_int hv1 ht1
            obtain ⟨b, rfl⟩ := canonical_int hv2 ht2
            exact Or.inr (Or.inl ⟨_, .cmpVal⟩)
          · exact Or.inr (Or.inl ⟨_, .cmpStep2 hv1 hstep2⟩)
          · exact Or.inr (Or.inr (.cmpStep2 hv1 hf2))
        · exact Or.inr (Or.inl ⟨_, .cmpStep1 hstep1⟩)
        · exact Or.inr (Or.inr (.cmpStep1 hf1))
      | cmpBool hop ht1 ht2 =>
        rcases ih1 ht1 with hv1 | ⟨e1', hstep1⟩ | hf1
        · rcases ih2 ht2 with hv2 | ⟨e2', hstep2⟩ | hf2
          · obtain ⟨a, rfl⟩ := canonical_bool hv1 ht1
            obtain ⟨b, rfl⟩ := canonical_bool hv2 ht2
            exact Or.inr (Or.inl ⟨_, .cmpBoolVal hop⟩)
          · exact Or.inr (Or.inl ⟨_, .cmpStep2 hv1 hstep2⟩)
          · exact Or.inr (Or.inr (.cmpStep2 hv1 hf2))
        · exact Or.inr (Or.inl ⟨_, .cmpStep1 hstep1⟩)
        · exact Or.inr (Or.inr (.cmpStep1 hf1))
  | neg h ih =>
      cases ht with
      | neg ht' =>
        rcases ih ht' with hv | ⟨e', hstep⟩ | hf
        · obtain ⟨n, rfl⟩ := canonical_int hv ht'
          rcases hr : evalNeg n with _ | m
          · exact Or.inr (Or.inr (.negBase hr))
          · exact Or.inr (Or.inl ⟨_, .negVal hr⟩)
        · exact Or.inr (Or.inl ⟨_, .negStep hstep⟩)
        · exact Or.inr (Or.inr (.negStep hf))
  | not h ih =>
      cases ht with
      | not ht' =>
        rcases ih ht' with hv | ⟨e', hstep⟩ | hf
        · obtain ⟨b, rfl⟩ := canonical_bool hv ht'
          exact Or.inr (Or.inl ⟨_, .notVal⟩)
        · exact Or.inr (Or.inl ⟨_, .notStep hstep⟩)
        · exact Or.inr (Or.inr (.notStep hf))
  | and h1 h2 ih1 ih2 =>
      cases ht with
      | and ht1 ht2 =>
        rcases ih1 ht1 with hv1 | ⟨e1', hstep1⟩ | hf1
        · obtain ⟨b, rfl⟩ := canonical_bool hv1 ht1
          cases b
          · exact Or.inr (Or.inl ⟨_, .andFalse⟩)
          · exact Or.inr (Or.inl ⟨_, .andTrue⟩)
        · exact Or.inr (Or.inl ⟨_, .andStep hstep1⟩)
        · exact Or.inr (Or.inr (.andStep hf1))
  | or h1 h2 ih1 ih2 =>
      cases ht with
      | or ht1 ht2 =>
        rcases ih1 ht1 with hv1 | ⟨e1', hstep1⟩ | hf1
        · obtain ⟨b, rfl⟩ := canonical_bool hv1 ht1
          cases b
          · exact Or.inr (Or.inl ⟨_, .orFalse⟩)
          · exact Or.inr (Or.inl ⟨_, .orTrue⟩)
        · exact Or.inr (Or.inl ⟨_, .orStep hstep1⟩)
        · exact Or.inr (Or.inr (.orStep hf1))
  | ite hc h1 h2 ihc ih1 ih2 =>
      cases ht with
      | ite htc ht1 ht2 =>
        rcases ihc htc with hv | ⟨c', hstep⟩ | hf
        · obtain ⟨b, rfl⟩ := canonical_bool hv htc
          cases b
          · exact Or.inr (Or.inl ⟨_, .iteFalse⟩)
          · exact Or.inr (Or.inl ⟨_, .iteTrue⟩)
        · exact Or.inr (Or.inl ⟨_, .iteStep hstep⟩)
        · exact Or.inr (Or.inr (.iteStep hf))

/-- The document's exact statement shape, specialized to a **closed**
(`Γ = []`) term. -/
theorem progress_scalarIf_closed {P e T} (hs : ScalarIf e) (ht : HasType P [] e T) :
    IsValue e ∨ (∃ e', Step P e e') ∨ FaultRedex e :=
  progress_scalarIf hs ht

/-! ## Preservation, full language

Unlike Progress, Preservation is stated and proved for **all** of Kernel-0,
`Let` and non-recursive `Call` included -- both beta rules substitute, so
this needs a substitution lemma and, for `Call`, `WellFormedProgram`. -/

theorem argsHaveTypes_length {P Γ env Ts} (h : ArgsHaveTypes P Γ env Ts) :
    env.length = Ts.length := by
  induction env generalizing Ts with
  | nil => cases h; rfl
  | cons e es ih =>
      cases h with
      | cons _ tl => simp [ih tl]

theorem argsHaveTypes_getElem? {P Γ env Ts} (h : ArgsHaveTypes P Γ env Ts) :
    ∀ (j : Nat) {T}, Ts[j]? = some T → ∃ v, env[j]? = some v ∧ HasType P Γ v T := by
  induction env generalizing Ts with
  | nil => intro j T hT; cases h; simp at hT
  | cons e es ih =>
      intro j T hT
      cases h with
      | cons hd tl =>
          cases j with
          | zero =>
              simp only [List.getElem?_cons_zero] at hT
              cases hT
              exact ⟨_, rfl, hd⟩
          | succ j' =>
              simp only [List.getElem?_cons_succ] at hT
              obtain ⟨v, hv, hty⟩ := ih tl j' hT
              exact ⟨v, hv, hty⟩

/-- A **value**'s typing derivation is independent of the context: both
`HasType` constructors for a literal (`intLit`/`boolLit`) ignore `Γ`
entirely. Needed below because Kernel-0's substitution only ever plugs in
values (`IsValue`), so re-typing `env` under a *different* context (as the
`letIn` case of `subst_preserves_type` needs, once `Γ1` grows by one entry)
is sound precisely because `env`'s elements have no free variables to begin
with -- not true of an arbitrary `Expr`, which is exactly why
`subst_preserves_type` needs this hypothesis threaded through rather than
holding unconditionally. -/
theorem hastype_value_any_context {P Γ Γ' v T} (hv : IsValue v) (h : HasType P Γ v T) :
    HasType P Γ' v T := by
  cases hv with
  | intLit n => cases h; exact HasType.intLit
  | boolLit b => cases h; exact HasType.boolLit

/-- The list form of `hastype_value_any_context`: a list of values' typing
against a fixed `Ts` is independent of context. -/
theorem argsHaveTypes_value_any_context {P Γ Γ' env Ts} (hvs : ∀ v ∈ env, IsValue v)
    (h : ArgsHaveTypes P Γ env Ts) : ArgsHaveTypes P Γ' env Ts := by
  induction env generalizing Ts with
  | nil => cases h; exact ArgsHaveTypes.nil
  | cons e es ih =>
      cases h with
      | cons hd tl =>
          exact ArgsHaveTypes.cons
            (hastype_value_any_context (hvs e List.mem_cons_self) hd)
            (ih (fun v hv => hvs v (List.mem_cons_of_mem _ hv)) tl)

/- `subst_preserves_type` and `subst_preserves_type_args` are defined
together in a `mutual` block: `subst_preserves_type`'s `call` case needs to
recurse into *each element* of `args : List Expr`, and `subst_preserves_type
_args` does exactly that, recursing back into `subst_preserves_type` on
each element in turn. Splitting the "recurse into a nested list field" half
into its own sibling function -- rather than reaching for `induction args`
*inside* `subst_preserves_type`'s own `call` case -- is not a style choice:
Lean 4.34's structural-recursion checker accepts a `mutual` pair whose
recursive calls sit directly on immediate pattern-matched subterms (`e1`,
`e2`, `a`, `as`, ...), matching exactly the support `substEnvAt`'s own
`args.map (substEnvAt base env)` already relies on, but it cannot discharge
termination for a *single* self-recursive function that reaches an element
several `induction`/`cases` steps deep inside its own tactic-mode proof
-- confirmed the hard way: that shape reliably produced "failed to infer
structural recursion" and, when forced into well-founded mode instead, an
unprovable-as-tried `sizeOf` side goal with no `a ∈ args` witness in scope
to discharge it. Recording this rather than silently landing on the
`mutual`-pair form, since it is exactly the kind of boundary a paper proof
never has to name. -/
mutual

/-- Substitution preserves typing: the key lemma Preservation needs for its
`letBeta`/`callBeta` cases. -/
theorem subst_preserves_type {P : Program} (Γ1 ΓMid Γ2 : List Ty) (env : List Expr) :
    ∀ (e : Expr) {T : Ty}, (∀ v ∈ env, IsValue v) →
      ArgsHaveTypes P (Γ1 ++ Γ2) env ΓMid →
      HasType P (Γ1 ++ ΓMid ++ Γ2) e T →
      HasType P (Γ1 ++ Γ2) (substEnvAt Γ1.length env e) T
  | .intLit n, _, henvVal, henv, ht => by cases ht; simp only [substEnvAt]; exact HasType.intLit
  | .boolLit b, _, henvVal, henv, ht => by cases ht; simp only [substEnvAt]; exact HasType.boolLit
  | .var i, T, henvVal, henv, ht => by
      cases ht with
      | var hget =>
        simp only [substEnvAt]
        -- Right-associate `Γ1 ++ ΓMid ++ Γ2` (parsed left-associatively as
        -- `(Γ1 ++ ΓMid) ++ Γ2`) so `List.getElem?_append_left/_right`'s
        -- `(l1 ++ l2)[i]?` pattern actually matches at each step.
        simp only [List.append_assoc] at hget
        by_cases h1 : i < Γ1.length
        · rw [if_pos h1]
          have hgoal : (Γ1 ++ Γ2)[i]? = some T := by
            rw [List.getElem?_append_left h1]
            rwa [List.getElem?_append_left h1] at hget
          exact HasType.var hgoal
        · rw [if_neg h1]
          have hlt2 : Γ1.length ≤ i := Nat.le_of_not_lt h1
          rw [List.getElem?_append_right hlt2] at hget
          have hlen := argsHaveTypes_length henv
          by_cases h2 : i - Γ1.length < env.length
          · rw [dif_pos h2]
            have h2' : i - Γ1.length < ΓMid.length := hlen ▸ h2
            rw [List.getElem?_append_left h2'] at hget
            obtain ⟨v, hv, hty⟩ := argsHaveTypes_getElem? henv (i - Γ1.length) hget
            obtain ⟨_, heq⟩ := List.getElem?_eq_some_iff.mp hv
            rw [heq]
            exact hty
          · rw [dif_neg h2]
            have hge : env.length ≤ i - Γ1.length := Nat.le_of_not_lt h2
            have hge' : ΓMid.length ≤ i - Γ1.length := hlen ▸ hge
            rw [List.getElem?_append_right hge'] at hget
            apply HasType.var
            have hidx : Γ1.length ≤ i - env.length := by omega
            rw [List.getElem?_append_right hidx]
            have hidxEq : i - env.length - Γ1.length = i - Γ1.length - ΓMid.length := by omega
            rw [hidxEq]
            exact hget
  | .arith op e1 e2, _, henvVal, henv, ht => by
      cases ht with
      | arith h1 h2 =>
        simp only [substEnvAt]
        exact HasType.arith (subst_preserves_type Γ1 ΓMid Γ2 env e1 henvVal henv h1)
          (subst_preserves_type Γ1 ΓMid Γ2 env e2 henvVal henv h2)
  | .cmp op e1 e2, _, henvVal, henv, ht => by
      cases ht with
      | cmpInt h1 h2 =>
        simp only [substEnvAt]
        exact HasType.cmpInt (subst_preserves_type Γ1 ΓMid Γ2 env e1 henvVal henv h1)
          (subst_preserves_type Γ1 ΓMid Γ2 env e2 henvVal henv h2)
      | cmpBool hop h1 h2 =>
        simp only [substEnvAt]
        exact HasType.cmpBool hop (subst_preserves_type Γ1 ΓMid Γ2 env e1 henvVal henv h1)
          (subst_preserves_type Γ1 ΓMid Γ2 env e2 henvVal henv h2)
  | .neg e1, _, henvVal, henv, ht => by
      cases ht with
      | neg h =>
        simp only [substEnvAt]
        exact HasType.neg (subst_preserves_type Γ1 ΓMid Γ2 env e1 henvVal henv h)
  | .not e1, _, henvVal, henv, ht => by
      cases ht with
      | not h =>
        simp only [substEnvAt]
        exact HasType.not (subst_preserves_type Γ1 ΓMid Γ2 env e1 henvVal henv h)
  | .and e1 e2, _, henvVal, henv, ht => by
      cases ht with
      | and h1 h2 =>
        simp only [substEnvAt]
        exact HasType.and (subst_preserves_type Γ1 ΓMid Γ2 env e1 henvVal henv h1)
          (subst_preserves_type Γ1 ΓMid Γ2 env e2 henvVal henv h2)
  | .or e1 e2, _, henvVal, henv, ht => by
      cases ht with
      | or h1 h2 =>
        simp only [substEnvAt]
        exact HasType.or (subst_preserves_type Γ1 ΓMid Γ2 env e1 henvVal henv h1)
          (subst_preserves_type Γ1 ΓMid Γ2 env e2 henvVal henv h2)
  | .ite c e1 e2, _, henvVal, henv, ht => by
      cases ht with
      | ite hc h1 h2 =>
        simp only [substEnvAt]
        exact HasType.ite (subst_preserves_type Γ1 ΓMid Γ2 env c henvVal henv hc)
          (subst_preserves_type Γ1 ΓMid Γ2 env e1 henvVal henv h1)
          (subst_preserves_type Γ1 ΓMid Γ2 env e2 henvVal henv h2)
  | .letIn e1 e2, _, henvVal, henv, ht => by
      cases ht with
      | letIn h1 h2 =>
        simp only [substEnvAt]
        refine HasType.letIn (subst_preserves_type Γ1 ΓMid Γ2 env e1 henvVal henv h1) ?_
        have hres := subst_preserves_type (_ :: Γ1) ΓMid Γ2 env e2 henvVal
          (argsHaveTypes_value_any_context henvVal henv) h2
        simpa using hres
  | .call f args, _, henvVal, henv, ht => by
      cases ht with
      | call hf hargs =>
        simp only [substEnvAt]
        exact HasType.call hf (subst_preserves_type_args Γ1 ΓMid Γ2 env args henvVal henv hargs)
termination_by structural e _ _ _ _ => e

/-- The `List Expr` half of the mutual pair above: maps `subst_preserves_type`
across every element of `args`, rebuilding the `ArgsHaveTypes` witness. -/
theorem subst_preserves_type_args {P : Program} (Γ1 ΓMid Γ2 : List Ty) (env : List Expr) :
    ∀ (args : List Expr) {Ts : List Ty}, (∀ v ∈ env, IsValue v) →
      ArgsHaveTypes P (Γ1 ++ Γ2) env ΓMid →
      ArgsHaveTypes P (Γ1 ++ ΓMid ++ Γ2) args Ts →
      ArgsHaveTypes P (Γ1 ++ Γ2) (args.map (substEnvAt Γ1.length env)) Ts
  | [], _, henvVal, henv, hargs => by
      cases hargs; simp only [List.map_nil]; exact ArgsHaveTypes.nil
  | a :: as, _, henvVal, henv, hargs => by
      cases hargs with
      | cons hd tl =>
          simp only [List.map_cons]
          exact ArgsHaveTypes.cons (subst_preserves_type Γ1 ΓMid Γ2 env a henvVal henv hd)
            (subst_preserves_type_args Γ1 ΓMid Γ2 env as henvVal henv tl)
termination_by structural args _ _ _ _ => args

end

/-- Self-contained helper (no dependency on a specific Std lemma name): if
`l1[i]? = some a` then `(l1 ++ l2)[i]? = some a`, by induction on `l1`. -/
theorem getElem?_append_left_of_some {α} :
    ∀ (l1 l2 : List α) (i : Nat) (a : α), l1[i]? = some a → (l1 ++ l2)[i]? = some a
  | [], _, _, _, h => by simp at h
  | _ :: _, l2, 0, a, h => by
      simp only [List.getElem?_cons_zero] at h ⊢
      exact h
  | _ :: tl, l2, (i' + 1), a, h => by
      simp only [List.cons_append, List.getElem?_cons_succ] at h ⊢
      exact getElem?_append_left_of_some tl l2 i' a h

/- Defined as a `mutual` pair with `hastype_weaken_right_args` for the same
reason `subst_preserves_type`/`subst_preserves_type_args` are: see that
pair's doc comment above. -/
mutual

/-- Appending extra, unreferenced context entries on the right preserves
typing. Needed to lift a `Fn`'s own body typing (`WellFormedProgram`, typed
under exactly `fd.params`) up to the caller's context `Γ` before
substituting the call's arguments into it. -/
theorem hastype_weaken_right {P : Program} (Γ1 Γ2 : List Ty) :
    ∀ (e : Expr) {T : Ty}, HasType P Γ1 e T → HasType P (Γ1 ++ Γ2) e T
  | .intLit n, _, h => by cases h; exact HasType.intLit
  | .boolLit b, _, h => by cases h; exact HasType.boolLit
  | .var i, _, h => by
      cases h with
      | var hget =>
        apply HasType.var
        exact getElem?_append_left_of_some Γ1 Γ2 i _ hget
  | .arith op e1 e2, _, h => by
      cases h with
      | arith h1 h2 =>
        exact HasType.arith (hastype_weaken_right Γ1 Γ2 e1 h1) (hastype_weaken_right Γ1 Γ2 e2 h2)
  | .cmp op e1 e2, _, h => by
      cases h with
      | cmpInt h1 h2 =>
        exact HasType.cmpInt (hastype_weaken_right Γ1 Γ2 e1 h1)
          (hastype_weaken_right Γ1 Γ2 e2 h2)
      | cmpBool hop h1 h2 =>
        exact HasType.cmpBool hop (hastype_weaken_right Γ1 Γ2 e1 h1)
          (hastype_weaken_right Γ1 Γ2 e2 h2)
  | .neg e1, _, h => by
      cases h with
      | neg h1 => exact HasType.neg (hastype_weaken_right Γ1 Γ2 e1 h1)
  | .not e1, _, h => by
      cases h with
      | not h1 => exact HasType.not (hastype_weaken_right Γ1 Γ2 e1 h1)
  | .and e1 e2, _, h => by
      cases h with
      | and h1 h2 =>
        exact HasType.and (hastype_weaken_right Γ1 Γ2 e1 h1) (hastype_weaken_right Γ1 Γ2 e2 h2)
  | .or e1 e2, _, h => by
      cases h with
      | or h1 h2 =>
        exact HasType.or (hastype_weaken_right Γ1 Γ2 e1 h1) (hastype_weaken_right Γ1 Γ2 e2 h2)
  | .ite c e1 e2, _, h => by
      cases h with
      | ite hc h1 h2 =>
        exact HasType.ite (hastype_weaken_right Γ1 Γ2 c hc) (hastype_weaken_right Γ1 Γ2 e1 h1)
          (hastype_weaken_right Γ1 Γ2 e2 h2)
  | .letIn e1 e2, _, h => by
      cases h with
      | letIn h1 h2 =>
        exact HasType.letIn (hastype_weaken_right Γ1 Γ2 e1 h1)
          (hastype_weaken_right (_ :: Γ1) Γ2 e2 h2)
  | .call f args, _, h => by
      cases h with
      | call hf hargs => exact HasType.call hf (hastype_weaken_right_args Γ1 Γ2 args hargs)
termination_by structural e _ => e

/-- The `List Expr` half of the mutual pair above. -/
theorem hastype_weaken_right_args {P : Program} (Γ1 Γ2 : List Ty) :
    ∀ (args : List Expr) {Ts : List Ty},
      ArgsHaveTypes P Γ1 args Ts → ArgsHaveTypes P (Γ1 ++ Γ2) args Ts
  | [], _, hargs => by cases hargs; exact ArgsHaveTypes.nil
  | a :: as, _, hargs => by
      cases hargs with
      | cons hd tl =>
          exact ArgsHaveTypes.cons (hastype_weaken_right Γ1 Γ2 a hd)
            (hastype_weaken_right_args Γ1 Γ2 as tl)
termination_by structural args _ => args

end

/-- Replacing one element of an argument list with another of the same type,
at any position, preserves `ArgsHaveTypes`. Needed for `Preservation`'s
`callArgs` congruence case. -/
theorem argsHaveTypes_replace {P : Program} {Γ : List Ty} :
    ∀ (vs : List Expr) (e e' : Expr) (es : List Expr) {Ts : List Ty},
      ArgsHaveTypes P Γ (vs ++ e :: es) Ts →
      (∀ T0, HasType P Γ e T0 → HasType P Γ e' T0) →
      ArgsHaveTypes P Γ (vs ++ e' :: es) Ts := by
  intro vs
  induction vs with
  | nil =>
      intro e e' es Ts h himp
      simp only [List.nil_append] at h ⊢
      cases h with
      | cons hd tl => exact ArgsHaveTypes.cons (himp _ hd) tl
  | cons v vs ih =>
      intro e e' es Ts h himp
      simp only [List.cons_append] at h ⊢
      cases h with
      | cons hd tl => exact ArgsHaveTypes.cons hd (ih e e' es tl himp)

/-- **Preservation.** If `e : T` and `e -> e'` then `e' : T`, for the whole
language including `Let` and non-recursive `Call`. Fully proved, **no
`sorry`** -- `WellFormedProgram P` is the one extra hypothesis mechanization
forced into the open (see the module doc comment above). -/
theorem preservation {P Γ e e' T} (hwf : WellFormedProgram P) (ht : HasType P Γ e T)
    (hs : Step P e e') : HasType P Γ e' T := by
  induction hs generalizing Γ T with
  | arithStep1 h ih => cases ht with | arith h1 h2 => exact HasType.arith (ih h1) h2
  | arithStep2 hv h ih => cases ht with | arith h1 h2 => exact HasType.arith h1 (ih h2)
  | arithVal h => cases ht with | arith _ _ => exact HasType.intLit
  | cmpStep1 h ih =>
      cases ht with
      | cmpInt h1 h2 => exact HasType.cmpInt (ih h1) h2
      | cmpBool hop h1 h2 => exact HasType.cmpBool hop (ih h1) h2
  | cmpStep2 hv h ih =>
      cases ht with
      | cmpInt h1 h2 => exact HasType.cmpInt h1 (ih h2)
      | cmpBool hop h1 h2 => exact HasType.cmpBool hop h1 (ih h2)
  | cmpVal =>
      cases ht with
      | cmpInt _ _ => exact HasType.boolLit
      | cmpBool _ h1 _ => cases h1
  | cmpBoolVal hop =>
      cases ht with
      | cmpInt h1 _ => cases h1
      | cmpBool _ _ _ => exact HasType.boolLit
  | negStep h ih => cases ht with | neg h1 => exact HasType.neg (ih h1)
  | negVal h => cases ht with | neg _ => exact HasType.intLit
  | notStep h ih => cases ht with | not h1 => exact HasType.not (ih h1)
  | notVal => cases ht with | not _ => exact HasType.boolLit
  | andStep h ih => cases ht with | and h1 h2 => exact HasType.and (ih h1) h2
  | andTrue => cases ht with | and _ h2 => exact h2
  | andFalse => cases ht with | and _ _ => exact HasType.boolLit
  | orStep h ih => cases ht with | or h1 h2 => exact HasType.or (ih h1) h2
  | orTrue => cases ht with | or _ _ => exact HasType.boolLit
  | orFalse => cases ht with | or _ h2 => exact h2
  | iteStep h ih => cases ht with | ite hc h1 h2 => exact HasType.ite (ih hc) h1 h2
  | iteTrue => cases ht with | ite _ h1 _ => exact h1
  | iteFalse => cases ht with | ite _ _ h2 => exact h2
  | letStep h ih => cases ht with | letIn h1 h2 => exact HasType.letIn (ih h1) h2
  | letBeta hv =>
      rename_i v e2
      cases ht with
      | letIn h1 h2 =>
        have henvVal : ∀ v' ∈ [v], IsValue v' := by
          intro v' hv'
          simp only [List.mem_singleton] at hv'
          subst hv'
          exact hv
        have hsub := subst_preserves_type (P := P) [] [_] Γ [_] _ henvVal
          (ArgsHaveTypes.cons h1 ArgsHaveTypes.nil) h2
        simpa [substAt] using hsub
  | callArgs hvs h ih =>
      cases ht with
      | call hf hargs =>
        exact HasType.call hf (argsHaveTypes_replace _ _ _ _ hargs (fun _ h0 => ih h0))
  | callBeta hargs hf =>
      rename_i f args fd
      cases ht
      rename_i fd' hf' hargs'
      have heq : (some fd' : Option FunDef) = some fd := hf'.symm.trans hf
      injection heq with hfdEq
      subst hfdEq
      have hbody : HasType P fd'.params fd'.body fd'.ret := hwf f fd' hf
      have hbody' : HasType P (fd'.params ++ Γ) fd'.body fd'.ret :=
        hastype_weaken_right fd'.params Γ fd'.body hbody
      have hsub := subst_preserves_type (P := P) [] fd'.params Γ args fd'.body hargs hargs' hbody'
      simpa using hsub

end Kernel0

/-! ## No-admitted-holes gate: `#print axioms` on every headline theorem

Each of these should report only Lean's standard axioms
(`propext`, `Classical.choice`, `Quot.sound`) or a subset -- never
`sorryAx` and never a custom axiom. This is the exact mechanical check
"no admitted holes" reduces to for Lean 4: `#print axioms <name>` (its
programmatic form is `#lint` or a script grepping the printed output for
the substring `sorryAx`). -/
#print axioms Kernel0.progress_scalarIf
#print axioms Kernel0.progress_scalarIf_closed
#print axioms Kernel0.preservation
#print axioms Kernel0.subst_preserves_type
#print axioms Kernel0.subst_preserves_type_args
#print axioms Kernel0.hastype_weaken_right
#print axioms Kernel0.hastype_weaken_right_args
#print axioms Kernel0.bool_equality_has_type
#print axioms Kernel0.bool_equality_steps
#print axioms Kernel0.bool_inequality_steps
#print axioms Kernel0.bool_ordering_is_not_typed
