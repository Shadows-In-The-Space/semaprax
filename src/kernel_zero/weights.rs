//! Executable certificate construction for the existing Lean weighted potential.
//!
//! Private proof-harness data only: these weights neither authorize execution nor
//! replace HIR validation. The Lean witness independently checks their meaning
//! against the actual lowered bodies. Checked `u64` arithmetic can refuse a large
//! acyclic graph whose mathematical natural-number certificate still exists.

use std::collections::{BTreeMap, BTreeSet};

use crate::hir::DeclarationId;

use super::term::{KernelProgram, Term};

const MAX_FUNCTIONS: usize = 64;
const MAX_NODES: usize = 8_192;
const MAX_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WeightError {
    DuplicateFunction,
    MissingFunction,
    Cycle,
    Limit,
    Overflow,
    InvalidCertificate,
}

pub(super) type Weights = BTreeMap<DeclarationId, u64>;

/// The least weights under this potential equation, computed once per callee.
/// Both branches and every argument participate even when execution is lazy.
pub(super) fn derive(program: &KernelProgram) -> Result<Weights, WeightError> {
    let functions = inventory(program)?;
    let mut weights = Weights::new();
    let mut active = BTreeSet::new();
    let mut nodes = 0;
    for id in functions.keys() {
        derive_function(id, &functions, &mut weights, &mut active, &mut nodes, 0)?;
    }
    Ok(weights)
}

fn inventory(program: &KernelProgram) -> Result<BTreeMap<DeclarationId, &Term>, WeightError> {
    if program.functions.len() > MAX_FUNCTIONS {
        return Err(WeightError::Limit);
    }
    let mut functions = BTreeMap::new();
    for function in &program.functions {
        if functions
            .insert(function.id.clone(), &function.body)
            .is_some()
        {
            return Err(WeightError::DuplicateFunction);
        }
    }
    Ok(functions)
}

fn derive_function(
    id: &DeclarationId,
    functions: &BTreeMap<DeclarationId, &Term>,
    weights: &mut Weights,
    active: &mut BTreeSet<DeclarationId>,
    nodes: &mut usize,
    depth: usize,
) -> Result<u64, WeightError> {
    if let Some(weight) = weights.get(id) {
        return Ok(*weight);
    }
    let body = functions.get(id).ok_or(WeightError::MissingFunction)?;
    if !active.insert(id.clone()) {
        return Err(WeightError::Cycle);
    }
    let potential = potential(body, nodes, depth, &mut |callee, nodes, depth| {
        derive_function(callee, functions, weights, active, nodes, depth)
    })?;
    let weight = add(potential, 1)?;
    active.remove(id);
    weights.insert(id.clone(), weight);
    Ok(weight)
}

fn add(left: u64, right: u64) -> Result<u64, WeightError> {
    left.checked_add(right).ok_or(WeightError::Overflow)
}

/// Mirrors the mathematical equation, without evaluation or constant folding.
fn potential(
    term: &Term,
    nodes: &mut usize,
    depth: usize,
    callee_weight: &mut impl FnMut(&DeclarationId, &mut usize, usize) -> Result<u64, WeightError>,
) -> Result<u64, WeightError> {
    if depth >= MAX_DEPTH || *nodes >= MAX_NODES {
        return Err(WeightError::Limit);
    }
    *nodes += 1;
    let child_depth = depth + 1;
    match term {
        Term::Int(_) | Term::Bool(_) | Term::Var(_) => Ok(1),
        Term::Unary(_, value) => add(potential(value, nodes, child_depth, callee_weight)?, 1),
        Term::Binary(_, left, right)
        | Term::Let {
            value: left,
            body: right,
            ..
        } => {
            let left = potential(left, nodes, child_depth, callee_weight)?;
            let right = potential(right, nodes, child_depth, callee_weight)?;
            add(add(left, right)?, 1)
        }
        Term::If {
            condition,
            then_branch,
            else_branch,
        } => {
            let condition = potential(condition, nodes, child_depth, callee_weight)?;
            let then_branch = potential(then_branch, nodes, child_depth, callee_weight)?;
            let else_branch = potential(else_branch, nodes, child_depth, callee_weight)?;
            add(add(add(condition, then_branch)?, else_branch)?, 1)
        }
        Term::Call { callee, args } => {
            let mut total = callee_weight(callee, nodes, child_depth)?;
            for argument in args {
                total = add(
                    total,
                    potential(argument, nodes, child_depth, callee_weight)?,
                )?;
            }
            Ok(total)
        }
    }
}

/// Replay the strict inequalities against supplied weights, without deriving
/// replacement weights. Extra, missing, zero, and insufficient entries fail.
pub(super) fn verify(program: &KernelProgram, weights: &Weights) -> Result<(), WeightError> {
    let functions = inventory(program)?;
    if !functions.keys().eq(weights.keys()) {
        return Err(WeightError::InvalidCertificate);
    }
    let mut nodes = 0;
    for (id, body) in &functions {
        let body_potential = potential(body, &mut nodes, 0, &mut |callee, _, _| {
            weights
                .get(callee)
                .copied()
                .ok_or(WeightError::MissingFunction)
        })?;
        if body_potential >= weights[id] {
            return Err(WeightError::InvalidCertificate);
        }
    }
    Ok(())
}

/// Numeric small-step budget for a call whose arguments are already values.
/// Lean's value potential is one, so the exact potential is weight + arity.
/// Typing and program well-formedness remain separate theorem hypotheses.
pub(super) fn value_call_fuel(
    program: &KernelProgram,
    weights: &Weights,
    entry: &DeclarationId,
) -> Result<u64, WeightError> {
    verify(program, weights)?;
    let function = program
        .function(entry)
        .ok_or(WeightError::MissingFunction)?;
    let arity = u64::try_from(function.params.len()).map_err(|_| WeightError::Overflow)?;
    add(weights[entry], arity)
}

#[cfg(test)]
mod tests {
    use super::super::term::{KernelFn, KernelType};
    use super::*;
    use crate::ast::BinaryOp;

    fn function(id: &str, body: Term) -> KernelFn {
        KernelFn {
            id: DeclarationId::new(id),
            params: vec![],
            return_type: KernelType::I64,
            body,
        }
    }

    fn call(id: &str) -> Term {
        Term::Call {
            callee: DeclarationId::new(id),
            args: vec![],
        }
    }

    #[test]
    fn derives_shared_callees_and_ignores_function_table_order() {
        let mut program = KernelProgram {
            functions: vec![
                function(
                    "a",
                    Term::Binary(BinaryOp::Add, Box::new(call("b")), Box::new(call("b"))),
                ),
                function("b", Term::Int(42)),
            ],
        };
        let weights = derive(&program).unwrap();
        assert_eq!(weights[&DeclarationId::new("a")], 6);
        assert_eq!(weights[&DeclarationId::new("b")], 2);
        assert_eq!(verify(&program, &weights), Ok(()));
        program.functions.reverse();
        assert_eq!(derive(&program), Ok(weights));
    }

    #[test]
    fn counts_unexecuted_branches_and_calls_nested_in_arguments() {
        let program = KernelProgram {
            functions: vec![
                function(
                    "a",
                    Term::If {
                        condition: Box::new(Term::Bool(false)),
                        then_branch: Box::new(Term::Call {
                            callee: DeclarationId::new("b"),
                            args: vec![call("b")],
                        }),
                        else_branch: Box::new(Term::Int(0)),
                    },
                ),
                function("b", Term::Int(1)),
            ],
        };
        assert_eq!(derive(&program).unwrap()[&DeclarationId::new("a")], 8);
    }

    #[test]
    fn refuses_cycles_even_in_unexecuted_call_arguments() {
        let program = KernelProgram {
            functions: vec![
                function(
                    "a",
                    Term::Call {
                        callee: DeclarationId::new("b"),
                        args: vec![call("a")],
                    },
                ),
                function("b", Term::Int(0)),
            ],
        };
        assert_eq!(derive(&program), Err(WeightError::Cycle));
    }

    #[test]
    fn refuses_ambiguous_and_dangling_function_identity() {
        assert_eq!(
            derive(&KernelProgram {
                functions: vec![function("a", call("b"))]
            }),
            Err(WeightError::MissingFunction)
        );
        assert_eq!(
            derive(&KernelProgram {
                functions: vec![function("a", Term::Int(0)), function("a", Term::Int(1))]
            }),
            Err(WeightError::DuplicateFunction)
        );
    }

    #[test]
    fn replay_refuses_underweight_extra_and_missing_entries() {
        let program = KernelProgram {
            functions: vec![function("a", Term::Int(0))],
        };
        let weights = derive(&program).unwrap();
        for amount in [0, 1] {
            let mut forged = weights.clone();
            forged.insert(DeclarationId::new("a"), amount);
            assert_eq!(
                verify(&program, &forged),
                Err(WeightError::InvalidCertificate)
            );
        }
        assert_eq!(
            verify(&program, &Weights::new()),
            Err(WeightError::InvalidCertificate)
        );
        let mut forged = weights;
        forged.insert(DeclarationId::new("extra"), 2);
        assert_eq!(
            verify(&program, &forged),
            Err(WeightError::InvalidCertificate)
        );
    }

    #[test]
    fn value_call_fuel_replays_certificate_and_charges_every_value_argument() {
        let mut entry = function("a", call("b"));
        entry.params = vec![
            (
                crate::hir::ValueId::intrinsic_parameter("a", 0),
                KernelType::I64,
            ),
            (
                crate::hir::ValueId::intrinsic_parameter("a", 1),
                KernelType::Bool,
            ),
        ];
        let program = KernelProgram {
            functions: vec![entry, function("b", Term::Int(42))],
        };
        let mut weights = derive(&program).unwrap();
        assert_eq!(
            value_call_fuel(&program, &weights, &DeclarationId::new("a")),
            Ok(5)
        );
        assert_eq!(
            value_call_fuel(&program, &weights, &DeclarationId::new("b")),
            Ok(2)
        );
        assert_eq!(
            value_call_fuel(&program, &weights, &DeclarationId::new("missing")),
            Err(WeightError::MissingFunction)
        );
        weights.insert(DeclarationId::new("a"), 2);
        assert_eq!(
            value_call_fuel(&program, &weights, &DeclarationId::new("a")),
            Err(WeightError::InvalidCertificate)
        );
        weights.insert(DeclarationId::new("a"), u64::MAX);
        assert_eq!(
            value_call_fuel(&program, &weights, &DeclarationId::new("a")),
            Err(WeightError::Overflow)
        );
    }

    #[test]
    fn exponential_dag_weight_refuses_arithmetic_overflow() {
        let functions = (0..64)
            .map(|index| {
                let id = format!("f{index:02}");
                let body = if index == 63 {
                    Term::Int(0)
                } else {
                    let next = format!("f{:02}", index + 1);
                    Term::Binary(BinaryOp::Add, Box::new(call(&next)), Box::new(call(&next)))
                };
                function(&id, body)
            })
            .collect();
        assert_eq!(
            derive(&KernelProgram { functions }),
            Err(WeightError::Overflow)
        );
    }

    #[test]
    fn refuses_traversal_limits_before_unbounded_work() {
        let functions = (0..65)
            .map(|i| function(&format!("f{i}"), Term::Int(0)))
            .collect();
        assert_eq!(
            derive(&KernelProgram { functions }),
            Err(WeightError::Limit)
        );
        let mut body = Term::Int(0);
        for _ in 0..128 {
            body = Term::Unary(crate::ast::UnaryOp::Neg, Box::new(body));
        }
        let program = KernelProgram {
            functions: vec![function("a", body)],
        };
        assert_eq!(derive(&program), Err(WeightError::Limit));
        let mut wide = KernelProgram {
            functions: vec![
                function(
                    "a",
                    Term::Call {
                        callee: DeclarationId::new("b"),
                        args: vec![Term::Int(0); 8_190],
                    },
                ),
                function("b", Term::Int(0)),
            ],
        };
        let weights = derive(&wide).expect("exact 8192-node boundary");
        assert_eq!(verify(&wide, &weights), Ok(()));
        if let Term::Call { args, .. } = &mut wide.functions[0].body {
            args.push(Term::Int(0));
        }
        assert_eq!(derive(&wide), Err(WeightError::Limit));
    }
}
