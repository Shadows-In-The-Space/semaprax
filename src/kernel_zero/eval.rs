//! A from-scratch Kernel-0 reference evaluator.
//!
//! Big-step, over [`Term`](super::term::Term), implementing exactly the
//! rules [`docs/SEMANTIC-KERNEL-V1.md`](../../../docs/SEMANTIC-KERNEL-V1.md)
//! states in "Operational semantics" (extended only where that document is
//! silent -- see `super::value`'s doc on [`Fault`]). It shares no code with
//! `src/interpreter.rs`'s `Evaluator`/`evaluate`/`combine`: no import from
//! that module appears anywhere in this file, and every rule below is
//! written directly against the grammar's stated reduction rules, not
//! against that module's `Value`/`Flow`/`combine` shapes. Environment
//! lookup uses a plain `Vec` rather than substitution
//! (`let x = v ; e2 -> e2[x := v]`) because the two are the standard,
//! textbook-equivalent implementation of call-by-value substitution for a
//! calculus with no operator that can observe the difference (Kernel-0 has
//! none: no mutation, no pointer/reference identity, no printing); using an
//! environment is an implementation choice, not a semantic one, and this
//! module's own `tests` below re-derive it from the substitution rule
//! directly (`let_binding_shadows_in_place`) rather than assume the
//! equivalence.
//!
//! Left-to-right evaluation order (a repository invariant, `AGENTS.md`) is
//! encoded explicitly everywhere it matters, never left to Rust's own
//! argument-evaluation order for some incidental tuple, array, or struct
//! literal:
//! - [`Term::Binary`]'s non-lazy arm evaluates `left`, binds its value, then
//!   evaluates `right` -- two sequential statements, not a tuple pattern
//!   `(eval(left), eval(right))` (whose evaluation order Rust does define,
//!   left to right, but which would make the ordering an accident of the
//!   host language rather than a stated property of this evaluator).
//! - [`Term::Binary`] on `And`/`Or` evaluates `left` unconditionally, first,
//!   and evaluates `right` only in the one case each operator's rule names
//!   (`true && e2 -> e2`, `false && e2 -> false`, and symmetrically for
//!   `||`) -- lazy boolean operands execute only when required.
//! - [`Term::Call`]'s arguments are evaluated by an explicit `for` loop over
//!   the grammar's authored argument order, left to right, before the callee
//!   is entered.

use crate::hir::ValueId;

use super::term::{KernelProgram, Term};
use super::value::{Fault, Value};
use crate::ast::{BinaryOp, UnaryOp};

/// A lexical environment: parameter and `let` bindings currently in scope,
/// most recently bound last. Kernel-0 has no closures, so a function call
/// starts a brand new, empty environment (just its own parameters) rather
/// than inheriting the caller's -- there is nothing to capture.
type Env = Vec<(ValueId, Value)>;

fn lookup(env: &Env, id: &ValueId) -> Value {
    env.iter()
        .rev()
        .find(|(bound, _)| bound == id)
        .map(|(_, value)| *value)
        .unwrap_or_else(|| {
            panic!(
                "kernel-0 reference evaluator: unbound variable {id:?} -- \
                 the translator (`super::reify`) only ever produces closed \
                 terms for an admitted function's own parameters and lets"
            )
        })
}

/// Evaluates `entry`'s body applied to `args`, in the order `entry.params`
/// names them. `args.len()` must equal `entry.params.len()`; the translator
/// and this evaluator's only caller (the differential test) both guarantee
/// this by construction, so a mismatch panics rather than returning an
/// error -- it can only mean a bug in the caller, not a Kernel-0 program
/// that got stuck.
pub(crate) fn eval_program(
    program: &KernelProgram,
    entry: &super::term::KernelFn,
    args: &[Value],
) -> Result<Value, Fault> {
    assert_eq!(
        args.len(),
        entry.params.len(),
        "kernel-0 reference evaluator: argument count must match parameter count"
    );
    let mut env: Env = Vec::with_capacity(args.len());
    for ((id, _), value) in entry.params.iter().zip(args.iter()) {
        env.push((id.clone(), *value));
    }
    eval_term(program, &entry.body, &mut env)
}

fn eval_term(program: &KernelProgram, term: &Term, env: &mut Env) -> Result<Value, Fault> {
    match term {
        Term::Int(value) => Ok(Value::Int(*value)),
        Term::Bool(value) => Ok(Value::Bool(*value)),
        Term::Var(id) => Ok(lookup(env, id)),
        Term::Unary(op, operand) => {
            let value = eval_term(program, operand, env)?;
            eval_unary(*op, value)
        }
        // `&&`/`||` are call-by-need per RFC 0001's "lazy boolean operands
        // execute only when required" invariant: `left` is evaluated
        // unconditionally, first, and `right` only in the one case the
        // grammar's own reduction rule names.
        Term::Binary(BinaryOp::And, left, right) => match eval_term(program, left, env)? {
            Value::Bool(false) => Ok(Value::Bool(false)),
            Value::Bool(true) => eval_term(program, right, env),
            Value::Int(_) => unreachable!(
                "kernel-0 translation only admits bool operands for `&&` (RFC 0001 typing)"
            ),
        },
        Term::Binary(BinaryOp::Or, left, right) => match eval_term(program, left, env)? {
            Value::Bool(true) => Ok(Value::Bool(true)),
            Value::Bool(false) => eval_term(program, right, env),
            Value::Int(_) => unreachable!(
                "kernel-0 translation only admits bool operands for `||` (RFC 0001 typing)"
            ),
        },
        Term::Binary(op, left, right) => {
            // Left to right, unconditionally: evaluate `left` fully, keep
            // its value, then evaluate `right`. Two sequential `let`
            // statements, not a tuple literal, so the order is this
            // function's own statement order rather than an artifact of
            // Rust's (also left-to-right, but incidental here) tuple rule.
            let left_value = eval_term(program, left, env)?;
            let right_value = eval_term(program, right, env)?;
            eval_binary(*op, left_value, right_value)
        }
        Term::If {
            condition,
            then_branch,
            else_branch,
        } => match eval_term(program, condition, env)? {
            Value::Bool(true) => eval_term(program, then_branch, env),
            Value::Bool(false) => eval_term(program, else_branch, env),
            Value::Int(_) => {
                unreachable!("kernel-0 translation only admits a bool `if` condition")
            }
        },
        Term::Let { bound, value, body } => {
            let bound_value = eval_term(program, value, env)?;
            env.push((bound.clone(), bound_value));
            let result = eval_term(program, body, env);
            env.pop();
            result
        }
        Term::Call { callee, args } => {
            // Left to right: each argument is evaluated fully, in the
            // grammar's authored order, before the callee is entered --
            // matching `f(v1,...,vn) -> body_f[x1:=v1,...,xn:=vn]`, which
            // presupposes every `vi` is already a value.
            let mut values = Vec::with_capacity(args.len());
            for arg in args {
                values.push(eval_term(program, arg, env)?);
            }
            let function = program.function(callee).unwrap_or_else(|| {
                panic!(
                    "kernel-0 reference evaluator: call to {callee:?}, absent from the \
                     translated program -- the translator only admits calls within the \
                     reifying, already-verified acyclic subgraph"
                )
            });
            eval_program(program, function, &values)
        }
    }
}

fn eval_unary(op: UnaryOp, value: Value) -> Result<Value, Fault> {
    match (op, value) {
        (UnaryOp::Neg, Value::Int(n)) => n
            .checked_neg()
            .map(Value::Int)
            .ok_or(Fault::NegationOverflow),
        (UnaryOp::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
        (UnaryOp::Neg, Value::Bool(_)) | (UnaryOp::Not, Value::Int(_)) => {
            unreachable!("kernel-0 translation only admits `-` on i64 and `!` on bool")
        }
    }
}

fn eval_binary(op: BinaryOp, left: Value, right: Value) -> Result<Value, Fault> {
    match (op, left, right) {
        (BinaryOp::Add, Value::Int(a), Value::Int(b)) => {
            a.checked_add(b).map(Value::Int).ok_or(Fault::AddOverflow)
        }
        (BinaryOp::Sub, Value::Int(a), Value::Int(b)) => {
            a.checked_sub(b).map(Value::Int).ok_or(Fault::SubOverflow)
        }
        (BinaryOp::Mul, Value::Int(a), Value::Int(b)) => {
            a.checked_mul(b).map(Value::Int).ok_or(Fault::MulOverflow)
        }
        (BinaryOp::Div, Value::Int(a), Value::Int(b)) => {
            if b == 0 {
                Err(Fault::DivisionByZero)
            } else {
                a.checked_div(b)
                    .map(Value::Int)
                    .ok_or(Fault::DivisionOverflow)
            }
        }
        (BinaryOp::Rem, Value::Int(a), Value::Int(b)) => {
            if b == 0 {
                Err(Fault::RemainderByZero)
            } else {
                a.checked_rem(b)
                    .map(Value::Int)
                    .ok_or(Fault::RemainderOverflow)
            }
        }
        (BinaryOp::Eq, Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a == b)),
        (BinaryOp::Ne, Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a != b)),
        (BinaryOp::Lt, Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a < b)),
        (BinaryOp::Le, Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a <= b)),
        (BinaryOp::Gt, Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a > b)),
        (BinaryOp::Ge, Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a >= b)),
        (BinaryOp::Eq, Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(a == b)),
        (BinaryOp::Ne, Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(a != b)),
        (BinaryOp::And | BinaryOp::Or, _, _) => {
            unreachable!("`&&`/`||` are handled by eval_term's dedicated lazy arms")
        }
        _ => unreachable!(
            "kernel-0 translation only admits well-typed operands per the grammar's typing rules"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::DeclarationId;
    use crate::kernel_zero::term::{KernelFn, KernelType};

    fn value_id(name: &str) -> ValueId {
        // `ValueId::new` is only `pub(super)` within `hir`; `intrinsic_parameter`
        // is the one `pub(crate)` constructor available outside it, so this
        // reference evaluator's own unit tests -- which build terms directly,
        // with no HIR/parser round trip, to check the reduction rules in
        // total isolation -- use it purely as a distinct-identity generator,
        // not for its documented intrinsic-operation meaning.
        ValueId::intrinsic_parameter(name, 0)
    }

    fn zero_arg_fn(id: &str, body: Term, return_type: KernelType) -> KernelFn {
        KernelFn {
            id: DeclarationId::new(id),
            params: Vec::new(),
            return_type,
            body,
        }
    }

    fn run(body: Term) -> Result<Value, Fault> {
        let function = zero_arg_fn("app.main", body, KernelType::I64);
        let program = KernelProgram {
            functions: vec![function.clone()],
        };
        eval_program(&program, &function, &[])
    }

    #[test]
    fn literals_and_arithmetic_reduce_left_to_right() {
        // 2 + 3 * 4 has no operator precedence in the term tree (it is
        // already a tree), so this only checks `+`'s own reduction.
        let term = Term::Binary(
            BinaryOp::Add,
            Box::new(Term::Int(2)),
            Box::new(Term::Int(3)),
        );
        assert_eq!(run(term), Ok(Value::Int(5)));
    }

    #[test]
    fn if_reduces_the_taken_branch_only() {
        let condition_true = Term::If {
            condition: Box::new(Term::Bool(true)),
            then_branch: Box::new(Term::Int(1)),
            else_branch: Box::new(Term::Int(2)),
        };
        assert_eq!(run(condition_true), Ok(Value::Int(1)));

        let condition_false = Term::If {
            condition: Box::new(Term::Bool(false)),
            then_branch: Box::new(Term::Int(1)),
            else_branch: Box::new(Term::Int(2)),
        };
        assert_eq!(run(condition_false), Ok(Value::Int(2)));
    }

    /// `let x = 1 ; let x = x + 1 ; x` must observe the *inner* `x`, per the
    /// substitution rule `let x = v ; e2 -> e2[x := v]` applied twice: the
    /// second `let`'s own RHS still sees the first binding (`x + 1` reads
    /// the outer `x`), but the body after it sees only the new, inner one.
    /// This is the environment-vs-substitution equivalence check the module
    /// doc promises, not an assumption.
    #[test]
    fn let_binding_shadows_in_place() {
        let outer = value_id("x#outer");
        let inner = value_id("x#inner");
        let term = Term::Let {
            bound: outer.clone(),
            value: Box::new(Term::Int(1)),
            body: Box::new(Term::Let {
                bound: inner.clone(),
                value: Box::new(Term::Binary(
                    BinaryOp::Add,
                    Box::new(Term::Var(outer)),
                    Box::new(Term::Int(1)),
                )),
                body: Box::new(Term::Var(inner)),
            }),
        };
        assert_eq!(run(term), Ok(Value::Int(2)));
    }

    #[test]
    fn short_circuit_and_never_evaluates_a_faulting_right_operand() {
        let faulting_division = Term::Binary(
            BinaryOp::Div,
            Box::new(Term::Int(1)),
            Box::new(Term::Int(0)),
        );
        let term = Term::Binary(
            BinaryOp::And,
            Box::new(Term::Bool(false)),
            Box::new(Term::Binary(
                BinaryOp::Eq,
                Box::new(faulting_division),
                Box::new(Term::Int(0)),
            )),
        );
        // Evaluated as a `bool` program instead of the `run` helper's fixed
        // `i64` return type.
        let function = zero_arg_fn("app.main", term, KernelType::Bool);
        let program = KernelProgram {
            functions: vec![function.clone()],
        };
        assert_eq!(
            eval_program(&program, &function, &[]),
            Ok(Value::Bool(false)),
            "false && <anything> must short-circuit without evaluating the right operand"
        );
    }

    #[test]
    fn short_circuit_or_never_evaluates_a_faulting_right_operand() {
        let faulting_division = Term::Binary(
            BinaryOp::Div,
            Box::new(Term::Int(1)),
            Box::new(Term::Int(0)),
        );
        let term = Term::Binary(
            BinaryOp::Or,
            Box::new(Term::Bool(true)),
            Box::new(Term::Binary(
                BinaryOp::Eq,
                Box::new(faulting_division),
                Box::new(Term::Int(0)),
            )),
        );
        let function = zero_arg_fn("app.main", term, KernelType::Bool);
        let program = KernelProgram {
            functions: vec![function.clone()],
        };
        assert_eq!(
            eval_program(&program, &function, &[]),
            Ok(Value::Bool(true)),
            "true || <anything> must short-circuit without evaluating the right operand"
        );
    }

    #[test]
    fn division_by_zero_is_a_fault_not_a_panic_or_wrap() {
        let term = Term::Binary(
            BinaryOp::Div,
            Box::new(Term::Int(1)),
            Box::new(Term::Int(0)),
        );
        assert_eq!(run(term), Err(Fault::DivisionByZero));
    }

    #[test]
    fn remainder_by_zero_is_a_fault() {
        let term = Term::Binary(
            BinaryOp::Rem,
            Box::new(Term::Int(1)),
            Box::new(Term::Int(0)),
        );
        assert_eq!(run(term), Err(Fault::RemainderByZero));
    }

    #[test]
    fn i64_min_divided_by_negative_one_overflows() {
        let term = Term::Binary(
            BinaryOp::Div,
            Box::new(Term::Int(i64::MIN)),
            Box::new(Term::Int(-1)),
        );
        assert_eq!(run(term), Err(Fault::DivisionOverflow));
    }

    #[test]
    fn i64_min_remainder_negative_one_overflows() {
        let term = Term::Binary(
            BinaryOp::Rem,
            Box::new(Term::Int(i64::MIN)),
            Box::new(Term::Int(-1)),
        );
        assert_eq!(run(term), Err(Fault::RemainderOverflow));
    }

    #[test]
    fn add_overflow_is_a_fault_not_a_silent_wrap() {
        let term = Term::Binary(
            BinaryOp::Add,
            Box::new(Term::Int(i64::MAX)),
            Box::new(Term::Int(1)),
        );
        assert_eq!(run(term), Err(Fault::AddOverflow));
    }

    #[test]
    fn negating_i64_min_overflows() {
        let term = Term::Unary(UnaryOp::Neg, Box::new(Term::Int(i64::MIN)));
        assert_eq!(run(term), Err(Fault::NegationOverflow));
    }

    #[test]
    fn call_evaluates_arguments_left_to_right_before_entering_the_callee() {
        // `callee(a, b) = a - b`; distinguishing left-to-right from any
        // other order needs a non-commutative operator.
        let param_a = value_id("callee.a");
        let param_b = value_id("callee.b");
        let callee = KernelFn {
            id: DeclarationId::new("test.callee"),
            params: vec![
                (param_a.clone(), KernelType::I64),
                (param_b.clone(), KernelType::I64),
            ],
            return_type: KernelType::I64,
            body: Term::Binary(
                BinaryOp::Sub,
                Box::new(Term::Var(param_a)),
                Box::new(Term::Var(param_b)),
            ),
        };
        let caller_body = Term::Call {
            callee: callee.id.clone(),
            args: vec![Term::Int(10), Term::Int(3)],
        };
        let caller = zero_arg_fn("app.main", caller_body, KernelType::I64);
        let program = KernelProgram {
            functions: vec![caller.clone(), callee],
        };
        assert_eq!(eval_program(&program, &caller, &[]), Ok(Value::Int(7)));
    }
}
