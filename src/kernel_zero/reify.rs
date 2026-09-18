//! Translation from a real `ResolvedFunction` to a Kernel-0 [`Term`].
//!
//! [`translate_program`] is defined only for a `DeclarationId` that
//! [`super::reifies_into_kernel_zero`] admits -- that predicate is the gate,
//! this translation is total on what it admits. Every branch below that
//! would need to translate an expression/statement/type kind outside
//! Kernel-0's grammar is an `unreachable!`, not a silent default: reaching
//! one would mean the predicate and this translator have drifted apart,
//! which is exactly the "compiler-to-model translation becomes the
//! unproved weak link" risk `docs/SEMANTIC-KERNEL-V1.md` names, so it must
//! be loud, not quietly wrong.
//!
//! This module reads `hir::ResolvedExpr`/`ResolvedStatement` shapes -- the
//! same read the predicate itself already does -- but calls nothing from
//! `src/interpreter.rs`. Translating "what this expression *is*" (its
//! grammar shape) is not evaluating it; the two stay independent.

use std::collections::HashSet;

use crate::hir::{
    DeclarationId, ResolvedExpr, ResolvedExprKind, ResolvedFunction, ResolvedProgram,
    ResolvedStatement, ResolvedType,
};

use super::term::{KernelFn, KernelProgram, KernelType, Term};

/// Translates the reifying subgraph reachable from `entry` (by `Call`) into
/// a [`KernelProgram`]. Returns `None` iff `entry` does not reify into
/// Kernel-0 per [`super::reifies_into_kernel_zero`] -- the only admission
/// decision this module makes; every other function below assumes it and
/// panics loudly if that assumption turns out false.
pub(crate) fn translate_program(
    program: &ResolvedProgram,
    entry: &DeclarationId,
) -> Option<KernelProgram> {
    if !super::reifies_into_kernel_zero(program, entry) {
        return None;
    }
    let mut functions = Vec::new();
    let mut seen = HashSet::new();
    let mut worklist = vec![entry.clone()];
    while let Some(id) = worklist.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        let function = program
            .functions
            .iter()
            .find(|candidate| candidate.id == id)
            .unwrap_or_else(|| {
                panic!(
                    "kernel-0 translator: {id:?} reifies per the admission predicate but is \
                     absent from the resolved program -- predicate/translator have drifted apart"
                )
            });
        let body = translate_expr(&function.body);
        let mut callees = Vec::new();
        collect_calls(&body, &mut callees);
        worklist.extend(callees);
        functions.push(translate_function(function, body));
    }
    Some(KernelProgram { functions })
}

fn translate_function(function: &ResolvedFunction, body: Term) -> KernelFn {
    KernelFn {
        id: function.id.clone(),
        params: function
            .params
            .iter()
            .map(|param| (param.id.clone(), translate_type(&param.ty)))
            .collect(),
        return_type: translate_type(&function.return_type),
        body,
    }
}

fn translate_type(ty: &ResolvedType) -> KernelType {
    match ty {
        ResolvedType::I64 => KernelType::I64,
        ResolvedType::Bool => KernelType::Bool,
        other => unreachable!(
            "kernel-0 translator: {other:?} is outside Kernel-0's `i64`/`bool` grammar; the \
             admission predicate must have rejected this function's declared type before this \
             translator ever saw it"
        ),
    }
}

fn translate_expr(expr: &ResolvedExpr) -> Term {
    match &expr.kind {
        ResolvedExprKind::Int(value) => Term::Int(*value),
        ResolvedExprKind::Bool(value) => Term::Bool(*value),
        ResolvedExprKind::Place(place) => {
            assert!(
                place.projections.is_empty(),
                "kernel-0 translator: a projected place is outside Kernel-0's grammar"
            );
            Term::Var(place.root.clone())
        }
        ResolvedExprKind::Unary { op, value } => Term::Unary(*op, Box::new(translate_expr(value))),
        ResolvedExprKind::Binary { op, left, right } => Term::Binary(
            *op,
            Box::new(translate_expr(left)),
            Box::new(translate_expr(right)),
        ),
        ResolvedExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => Term::If {
            condition: Box::new(translate_expr(condition)),
            then_branch: Box::new(translate_expr(then_branch)),
            else_branch: Box::new(translate_expr(else_branch)),
        },
        ResolvedExprKind::Block { statements, tail } => {
            // Fold right-to-left so the innermost `Let` wraps the tail and
            // each outer one wraps the one before it -- exactly the nested
            // `let x1 = e1 ; let x2 = e2 ; ... ; tail` shape the grammar's
            // `Block` sugar for sequential `let`s expands to.
            statements
                .iter()
                .rev()
                .fold(translate_expr(tail), |body, statement| {
                    let ResolvedStatement::Let {
                        binding,
                        mutable,
                        value,
                        ..
                    } = statement
                    else {
                        unreachable!(
                            "kernel-0 translator: only immutable `Let` statements reify; \
                         `Assign`/`Unsafe` must have been rejected by the admission predicate"
                        );
                    };
                    assert!(
                        !mutable,
                        "kernel-0 translator: a mutable `let` is outside Kernel-0's grammar"
                    );
                    Term::Let {
                        bound: binding.id.clone(),
                        value: Box::new(translate_expr(value)),
                        body: Box::new(body),
                    }
                })
        }
        ResolvedExprKind::Call {
            callee,
            type_arguments,
            instance,
            args,
        } => {
            assert!(
                type_arguments.is_empty() && instance.is_none(),
                "kernel-0 translator: a generic/instance call is outside Kernel-0's grammar"
            );
            Term::Call {
                callee: callee.clone(),
                args: args.iter().map(translate_expr).collect(),
            }
        }
        other => unreachable!(
            "kernel-0 translator: {other:?} is outside Kernel-0's grammar; the admission \
             predicate must have rejected the function containing it before this translator \
             ever saw it"
        ),
    }
}

/// Collects every `Call` target reachable from `term`, in no particular
/// order (the caller only uses this to grow a worklist, not to fix
/// evaluation order -- [`super::eval`] alone owns that).
fn collect_calls(term: &Term, out: &mut Vec<DeclarationId>) {
    match term {
        Term::Int(_) | Term::Bool(_) | Term::Var(_) => {}
        Term::Unary(_, value) => collect_calls(value, out),
        Term::Binary(_, left, right) => {
            collect_calls(left, out);
            collect_calls(right, out);
        }
        Term::If {
            condition,
            then_branch,
            else_branch,
        } => {
            collect_calls(condition, out);
            collect_calls(then_branch, out);
            collect_calls(else_branch, out);
        }
        Term::Let { value, body, .. } => {
            collect_calls(value, out);
            collect_calls(body, out);
        }
        Term::Call { callee, args } => {
            out.push(callee.clone());
            for arg in args {
                collect_calls(arg, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::translate_program;
    use crate::hir;
    use crate::kernel_zero::eval::eval_program;
    use crate::kernel_zero::value::Value;

    fn resolve(source: &str) -> hir::ResolvedProgram {
        let program = crate::parse(source, "kernel-zero-reify-test.spx").expect("must parse");
        hir::resolve(&program).expect("must resolve")
    }

    fn function_id(program: &hir::ResolvedProgram, name: &str) -> hir::DeclarationId {
        program
            .functions
            .iter()
            .find(|function| function.name == name)
            .map(|function| function.id.clone())
            .unwrap_or_else(|| panic!("no resolved function named {name}"))
    }

    #[test]
    fn non_reifying_function_translates_to_none() {
        let source = "module test.kernel_zero_reify;\n\n\
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
        assert!(translate_program(&program, &id).is_none());
    }

    /// End-to-end sanity check with no comparison to the real compiler
    /// backend (that is the differential test's job): translating and then
    /// evaluating a small multi-function, `let`/`if`/call/arithmetic module
    /// -- the same shape `src/kernel_zero.rs`'s own
    /// `kernel_zero_shaped_functions_reify` test admits -- must reduce to
    /// the value plain arithmetic predicts: `add(19, 23) = 42`,
    /// `classify(42) = 1` (`42 < 0` is false), so `main() = 43`.
    #[test]
    fn translated_module_evaluates_to_the_arithmetically_expected_result() {
        let source = "module test.kernel_zero_reify;\n\n\
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
        let entry = function_id(&program, "main");
        let kernel_program = translate_program(&program, &entry).expect("main reifies");
        let entry_fn = kernel_program.function(&entry).expect("entry present");
        assert_eq!(
            eval_program(&kernel_program, entry_fn, &[]),
            Ok(Value::Int(43))
        );
    }
}
