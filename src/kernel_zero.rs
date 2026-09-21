//! Executable Kernel-0 reification predicate.
//!
//! [`docs/SEMANTIC-KERNEL-V1.md`](../../docs/SEMANTIC-KERNEL-V1.md)
//! ("Reification: HIR to Kernel-0, and its unproved edge") states, in prose
//! only, the exact admission predicate a real `ResolvedFunction` must
//! satisfy to reify into the paper-proved Kernel-0 term calculus that
//! document's "Paper safety proof" section covers. That document names
//! implementing this predicate as executable code, with a test, as its
//! highest-priority open follow-up for
//! [issue #188](https://github.com/wavect/semaprax/issues/188): until it
//! exists, the Kernel-0 proof is about a term-rewriting system on paper with
//! no checked connection to any real compiler pass.
//!
//! This module is that predicate, [`reifies_into_kernel_zero`], implemented
//! directly against `hir::ResolvedProgram`/`ResolvedFunction` with no parser
//! or codegen dependency. It is deliberately a pure yes/no admission check,
//! not a translator into a separate term type: the specification document
//! defines Kernel-0 as a syntactic restriction of the real grammar, so a
//! function that reifies is already checked, compiled, and run by the real,
//! unmodified toolchain -- this predicate only decides which functions that
//! existing claim covers.
//!
//! What this closes, and what it still leaves open, per the specification
//! document's own "Non-claims" section:
//! - It makes the reification predicate real and mechanically checked
//!   instead of prose-only, for the "does this `ResolvedFunction` reify"
//!   half of the gap; see this module's tests.
//! - A later session added the from-scratch Kernel-0 reference interpreter
//!   and differential test this bullet used to say did not exist:
//!   `eval`/`term`/`value`/`reify` (the reference interpreter and HIR
//!   translator, always compiled) and `corpus`/`differential`
//!   (`#[cfg(test)]`-only: the deterministic generator and the differential
//!   test itself). It compares only the **interpreter** backend, over a
//!   finite seeded corpus -- see the specification document's "Differential
//!   testing" section for the corpus, the seed, the result, and two gaps in
//!   this document's own stated grammar/semantics that writing an
//!   independent evaluator against it surfaced. The native and Wasm
//!   backends, and any corpus larger than this session's, remain open --
//!   see the specification document's "Immediate follow-ups", item 1.
//! - It is stricter than the document's stated prose predicate in one way:
//!   it additionally requires empty `requires`/`ensures` contract lists.
//!   Kernel-0's grammar (in the specification document) has no contract
//!   clause at all, so a function with a non-trivial `requires`/`ensures`
//!   cannot be reduced to a Kernel-0 term without silently dropping
//!   obligations the real compiler enforces -- the original prose predicate
//!   did not mention this case, and this implementation closes that
//!   omission conservatively (reject, never admit) rather than reproduce it.

use crate::hir::{
    DeclarationId, OwnershipMode, Place, ResolvedExpr, ResolvedExprKind, ResolvedFunction,
    ResolvedProgram, ResolvedStatement, ResolvedType,
};
use std::collections::HashSet;

// The from-scratch Kernel-0 reference interpreter (term grammar, evaluator,
// and HIR translator) plus the deterministic corpus generator and
// differential test that checks it against the real compiler -- see each
// module's own doc comment, and "Reification: HIR to Kernel-0, and its
// unproved edge" / "Immediate follow-ups" in
// `docs/SEMANTIC-KERNEL-V1.md` for why this exists.
mod eval;
mod reify;
mod term;
mod value;

// The deterministic corpus generator and the differential test itself are
// test-only infrastructure, not part of the reference interpreter proper.
#[cfg(test)]
mod corpus;
#[cfg(test)]
mod differential;
#[cfg(test)]
mod graph_projection;
#[cfg(test)]
mod lean_fixture;
#[cfg(test)]
mod rung_two_renderer;
#[cfg(test)]
mod transaction;
#[cfg(test)]
mod weights;

/// Returns `true` iff the function declared as `id` in `program` reifies
/// into Kernel-0, per this module's predicate. `false` covers both "no such
/// function" and "found, but does not reify" -- callers that need to
/// distinguish those, or need the specific reason, are not served by this
/// boolean gate; none of this module's current callers need that
/// distinction.
///
/// A cyclic `Call` subgraph (`f` reachable from itself) never reifies,
/// matching Kernel-0's grammar note that "the call graph among Kernel-0 Fns
/// is acyclic."
pub(crate) fn reifies_into_kernel_zero(program: &ResolvedProgram, id: &DeclarationId) -> bool {
    let mut visiting = HashSet::new();
    function_reifies(program, id, &mut visiting)
}

fn function_reifies(
    program: &ResolvedProgram,
    id: &DeclarationId,
    visiting: &mut HashSet<DeclarationId>,
) -> bool {
    if !visiting.insert(id.clone()) {
        // Already on the current call path: entering it again would make
        // the reachable-by-`Call` subgraph cyclic.
        return false;
    }
    let reifies = program
        .functions
        .iter()
        .find(|function| &function.id == id)
        .is_some_and(|function| function_body_reifies(program, function, visiting));
    visiting.remove(id);
    reifies
}

fn function_body_reifies(
    program: &ResolvedProgram,
    function: &ResolvedFunction,
    visiting: &mut HashSet<DeclarationId>,
) -> bool {
    function.effects.is_empty()
        && function.requires.is_empty()
        && function.ensures.is_empty()
        && is_kernel_scalar(&function.return_type)
        // `param.ownership == OwnershipMode::Value` is the literal
        // translation of the specification document's "no own/borrow
        // parameter... mode" clause. Confirmed against the built CLI while
        // writing this module: the compiler itself refuses `own`/`borrow`
        // on any Copy value type with `SPX-O002` ("ownership mode ... is
        // only valid for resource types"), so no admitted source can ever
        // combine an `i64`/`bool` parameter with a non-`Value` ownership
        // mode -- this conjunct is unreachable for anything that also
        // passes `is_kernel_scalar` below, and no test in this module's
        // `tests` submodule exercises it directly for that reason. Kept
        // anyway as the faithful, defensive translation of the stated
        // predicate rather than silently dropped.
        && function
            .params
            .iter()
            .all(|param| param.ownership == OwnershipMode::Value && is_kernel_scalar(&param.ty))
        && expr_reifies(program, &function.body, visiting)
}

fn is_kernel_scalar(ty: &ResolvedType) -> bool {
    matches!(ty, ResolvedType::I64 | ResolvedType::Bool)
}

fn is_kernel_place(place: &Place) -> bool {
    // Kernel-0 has no records/variants, so a reifying place is a bare
    // parameter or let-bound name with no field projection at all.
    place.projections.is_empty()
}

fn expr_reifies(
    program: &ResolvedProgram,
    expr: &ResolvedExpr,
    visiting: &mut HashSet<DeclarationId>,
) -> bool {
    if expr.ownership != OwnershipMode::Value || !is_kernel_scalar(&expr.ty) {
        return false;
    }
    match &expr.kind {
        ResolvedExprKind::Int(_) | ResolvedExprKind::Bool(_) => true,
        ResolvedExprKind::Place(place) => is_kernel_place(place),
        ResolvedExprKind::Unary { value, .. } => expr_reifies(program, value, visiting),
        ResolvedExprKind::Binary { left, right, .. } => {
            expr_reifies(program, left, visiting) && expr_reifies(program, right, visiting)
        }
        ResolvedExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            expr_reifies(program, condition, visiting)
                && expr_reifies(program, then_branch, visiting)
                && expr_reifies(program, else_branch, visiting)
        }
        ResolvedExprKind::Block { statements, tail } => {
            statements
                .iter()
                .all(|statement| statement_reifies(program, statement, visiting))
                && expr_reifies(program, tail, visiting)
        }
        ResolvedExprKind::Call {
            callee,
            type_arguments,
            instance,
            args,
        } => {
            type_arguments.is_empty()
                && instance.is_none()
                && args.iter().all(|arg| expr_reifies(program, arg, visiting))
                && function_reifies(program, callee, visiting)
        }
        // Every other expression kind (records/variants, match, closures,
        // try/try-option, byte ranges, native/host calls, ...) is outside
        // Kernel-0's grammar by construction; see "What Kernel-0
        // deliberately excludes" in the specification document.
        _ => false,
    }
}

fn statement_reifies(
    program: &ResolvedProgram,
    statement: &ResolvedStatement,
    visiting: &mut HashSet<DeclarationId>,
) -> bool {
    match statement {
        ResolvedStatement::Let { mutable, value, .. } => {
            !*mutable && expr_reifies(program, value, visiting)
        }
        // `Assign` (Explicit Mutation v1) and `Unsafe` are both outside
        // Kernel-0's grammar, which has no mutation and no unsafe blocks.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::reifies_into_kernel_zero;
    use crate::hir;

    fn resolve(source: &str) -> hir::ResolvedProgram {
        let program = crate::parse(source, "kernel-zero-test.spx").expect("source must parse");
        hir::resolve(&program).expect("source must resolve")
    }

    fn function_id(program: &hir::ResolvedProgram, name: &str) -> hir::DeclarationId {
        program
            .functions
            .iter()
            .find(|function| function.name == name)
            .map(|function| function.id.clone())
            .unwrap_or_else(|| panic!("no resolved function named {name}"))
    }

    /// The exact two-function module `docs/SEMANTIC-KERNEL-V1.md`'s "Rung 0
    /// evidence" section hand-ran across all three backends: scalars, `if`,
    /// `let`, arithmetic/comparison, and a non-recursive call. This is the
    /// positive case the predicate exists to admit.
    #[test]
    fn kernel_zero_shaped_functions_reify() {
        let source = "module test.kernel_zero;\n\n\
             @id(\"test.add\")\n\
             fn add(left: i64, right: i64) -> i64\n\
             {\n\
             \x20   left + right\n\
             }\n\n\
             @id(\"test.classify\")\n\
             fn classify(value: i64) -> i64\n\
             {\n\
             \x20   if value < 0 { 0 } else { 1 }\n\
             }\n\n\
             @id(\"app.main\")\n\
             fn main() -> i64\n\
             {\n\
             \x20   let sum = add(19, 23);\n\
             \x20   sum + classify(42)\n\
             }\n";
        let program = resolve(source);
        for name in ["add", "classify", "main"] {
            let id = function_id(&program, name);
            assert!(
                reifies_into_kernel_zero(&program, &id),
                "{name} matches Kernel-0's grammar exactly and must reify"
            );
        }
    }

    /// A `bool`-typed classifier using `&&` and nested `let`s stays within
    /// Kernel-0 too -- the predicate must not be scalar-type-biased toward
    /// `i64` alone.
    #[test]
    fn boolean_kernel_zero_function_reifies() {
        let source = "module test.kernel_zero;\n\n\
             @id(\"test.in_range\")\n\
             fn in_range(value: i64) -> bool\n\
             {\n\
             \x20   let low = value > 0;\n\
             \x20   let high = value < 100;\n\
             \x20   low && high\n\
             }\n\n\
             @id(\"app.main\")\n\
             fn main() -> i64\n\
             {\n\
             \x20   0\n\
             }\n";
        let program = resolve(source);
        let id = function_id(&program, "in_range");
        assert!(reifies_into_kernel_zero(&program, &id));
    }

    /// A declared effect (`uses`) takes a function outside Kernel-0's pure
    /// fragment even though its body is otherwise scalars-only. Verified
    /// admitted syntax: a module-level `permit` naming the same capability
    /// the function's `uses` clause names.
    #[test]
    fn function_with_an_effect_does_not_reify() {
        let source = "module test.kernel_zero;\n\n\
             permit { clock.read }\n\n\
             @id(\"test.touches_clock\")\n\
             fn touches_clock() -> i64\n\
             \x20   uses { clock.read }\n\
             {\n\
             \x20   1\n\
             }\n\n\
             @id(\"app.main\")\n\
             fn main() -> i64\n\
             \x20   uses { clock.read }\n\
             {\n\
             \x20   touches_clock()\n\
             }\n";
        let program = resolve(source);
        let id = function_id(&program, "touches_clock");
        assert!(!reifies_into_kernel_zero(&program, &id));
    }

    /// A record type is outside Kernel-0's grammar (no records/variants),
    /// so a function returning one must not reify, and neither must a
    /// caller of it, transitively.
    #[test]
    fn function_using_a_record_does_not_reify_and_neither_does_its_caller() {
        let source = "module test.kernel_zero;\n\n\
             @id(\"test.pair\")\n\
             record Pair {\n\
             \x20   @id(\"test.pair.left\")\n\
             \x20   left: i64,\n\
             \x20   @id(\"test.pair.right\")\n\
             \x20   right: i64,\n\
             }\n\n\
             @id(\"test.make_pair\")\n\
             fn make_pair() -> Pair\n\
             {\n\
             \x20   Pair { left: 1, right: 2 }\n\
             }\n\n\
             @id(\"test.calls_it\")\n\
             fn calls_it() -> i64\n\
             {\n\
             \x20   let pair = make_pair();\n\
             \x20   pair.left\n\
             }\n\n\
             @id(\"app.main\")\n\
             fn main() -> i64\n\
             {\n\
             \x20   calls_it()\n\
             }\n";
        let program = resolve(source);
        assert!(!reifies_into_kernel_zero(
            &program,
            &function_id(&program, "make_pair")
        ));
        assert!(!reifies_into_kernel_zero(
            &program,
            &function_id(&program, "calls_it")
        ));
    }

    /// A contract clause (`requires`) takes a function outside Kernel-0's
    /// grammar, which has no contract syntax at all -- the stricter check
    /// this module's doc comment names as a deliberate refinement of the
    /// specification document's original prose predicate.
    #[test]
    fn function_with_a_requires_clause_does_not_reify() {
        let source = "module test.kernel_zero;\n\n\
             @id(\"test.halve\")\n\
             fn halve(value: i64) -> i64\n\
             \x20   requires value >= 0\n\
             {\n\
             \x20   value / 2\n\
             }\n\n\
             @id(\"app.main\")\n\
             fn main() -> i64\n\
             {\n\
             \x20   halve(4)\n\
             }\n";
        let program = resolve(source);
        let id = function_id(&program, "halve");
        assert!(!reifies_into_kernel_zero(&program, &id));
    }

    /// A mutually recursive pair of functions never reifies, matching the
    /// specification document's "the call graph among Kernel-0 Fns is
    /// acyclic" grammar note: entering a function already on the current
    /// call path is refused before either function's own shape is even
    /// considered.
    #[test]
    fn mutually_recursive_functions_do_not_reify() {
        let source = "module test.kernel_zero;\n\n\
             @id(\"test.ping\")\n\
             fn ping(value: i64) -> i64\n\
             {\n\
             \x20   if value <= 0 { 0 } else { pong(value - 1) }\n\
             }\n\n\
             @id(\"test.pong\")\n\
             fn pong(value: i64) -> i64\n\
             {\n\
             \x20   if value <= 0 { 0 } else { ping(value - 1) }\n\
             }\n\n\
             @id(\"app.main\")\n\
             fn main() -> i64\n\
             {\n\
             \x20   ping(3)\n\
             }\n";
        let program = resolve(source);
        assert!(!reifies_into_kernel_zero(
            &program,
            &function_id(&program, "ping")
        ));
        assert!(!reifies_into_kernel_zero(
            &program,
            &function_id(&program, "pong")
        ));
    }
}
