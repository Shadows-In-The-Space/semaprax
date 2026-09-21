//! Bounded, independent typing derivations for the real reified corpus.
//!
//! This is a proof-term producer, not a trusted typing oracle: Lean checks the
//! emitted constructors against the exact named term, signature table and local
//! environment. It does not inspect HIR annotations or reuse resolver typing.
//! Refusals are private harness errors, never language-admission diagnostics.

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::{BinaryOp, UnaryOp};
use crate::hir::{DeclarationId, ValueId};

use super::super::term::{KernelProgram, KernelType, Term};

const MAX_FUNCTIONS: usize = 64;
const MAX_NODES: usize = 8_192;
const MAX_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TypingError {
    Limit,
    DuplicateFunction,
    DuplicateParameter,
    MissingFunction,
    UnboundVariable,
    TypeMismatch,
    ArityMismatch,
    DefinitionInventory,
}

/// One proof per actual body, in authored function-table order. All signatures
/// are available before any body is walked; this does not assert acyclicity.
pub(super) fn derive(
    program: &KernelProgram,
    definitions: &[String],
) -> Result<Vec<String>, TypingError> {
    if program.functions.len() > MAX_FUNCTIONS {
        return Err(TypingError::Limit);
    }
    if definitions.len() != program.functions.len() {
        return Err(TypingError::DefinitionInventory);
    }
    let mut functions = BTreeMap::new();
    let mut nodes = 0;
    for (index, function) in program.functions.iter().enumerate() {
        if functions.insert(function.id.clone(), index).is_some() {
            return Err(TypingError::DuplicateFunction);
        }
        charge(&mut nodes, function.params.len())?;
        let mut seen = BTreeSet::new();
        for (id, _) in &function.params {
            if !seen.insert(id) {
                return Err(TypingError::DuplicateParameter);
            }
        }
    }
    let mut checker = Checker {
        program,
        functions,
        definitions,
        nodes,
    };
    program
        .functions
        .iter()
        .map(|function| {
            let mut locals = function.params.clone();
            let (ty, proof) = checker.term(&function.body, &mut locals, 0)?;
            same(ty, function.return_type)?;
            Ok(proof)
        })
        .collect()
}

/// Independently re-check one closed runtime term against the already-admitted
/// function signature table. Used by the concrete normalization witness after
/// every small step; it emits no Lean text and grants no compiler authority.
pub(super) fn check_closed_term(
    program: &KernelProgram,
    term: &Term,
    expected: KernelType,
) -> Result<(), TypingError> {
    if program.functions.len() > MAX_FUNCTIONS {
        return Err(TypingError::Limit);
    }
    let definitions = (0..program.functions.len())
        .map(|index| format!("runtimeDefinition{index}"))
        .collect::<Vec<_>>();
    let mut functions = BTreeMap::new();
    let mut nodes = 0;
    for (index, function) in program.functions.iter().enumerate() {
        if functions.insert(function.id.clone(), index).is_some() {
            return Err(TypingError::DuplicateFunction);
        }
        charge(&mut nodes, function.params.len())?;
        let mut seen = BTreeSet::new();
        for (id, _) in &function.params {
            if !seen.insert(id) {
                return Err(TypingError::DuplicateParameter);
            }
        }
    }
    let mut checker = Checker {
        program,
        functions,
        definitions: &definitions,
        nodes,
    };
    let (actual, _) = checker.term(term, &mut Vec::new(), 0)?;
    same(actual, expected)
}

fn charge(nodes: &mut usize, amount: usize) -> Result<(), TypingError> {
    *nodes = nodes.checked_add(amount).ok_or(TypingError::Limit)?;
    if *nodes > MAX_NODES {
        return Err(TypingError::Limit);
    }
    Ok(())
}

fn same(actual: KernelType, expected: KernelType) -> Result<(), TypingError> {
    if actual == expected {
        Ok(())
    } else {
        Err(TypingError::TypeMismatch)
    }
}

struct Checker<'a> {
    program: &'a KernelProgram,
    functions: BTreeMap<DeclarationId, usize>,
    definitions: &'a [String],
    nodes: usize,
}

impl Checker<'_> {
    fn term(
        &mut self,
        term: &Term,
        locals: &mut Vec<(ValueId, KernelType)>,
        depth: usize,
    ) -> Result<(KernelType, String), TypingError> {
        if depth > MAX_DEPTH {
            return Err(TypingError::Limit);
        }
        charge(&mut self.nodes, 1)?;
        let (ty, rule, proofs) = match term {
            Term::Int(_) => (KernelType::I64, "intLit", vec![]),
            Term::Bool(_) => (KernelType::Bool, "boolLit", vec![]),
            Term::Var(id) => {
                let ty = locals
                    .iter()
                    .find(|(name, _)| name == id)
                    .map(|(_, ty)| *ty)
                    .ok_or(TypingError::UnboundVariable)?;
                (ty, "var", vec!["by rfl".to_owned()])
            }
            Term::Unary(op, value) => {
                let (ty, proof) = self.term(value, locals, depth + 1)?;
                let (expected, rule) = match op {
                    UnaryOp::Neg => (KernelType::I64, "neg"),
                    UnaryOp::Not => (KernelType::Bool, "not"),
                };
                same(ty, expected)?;
                (expected, rule, vec![proof])
            }
            Term::Binary(op, left, right) => {
                let (left_ty, left) = self.term(left, locals, depth + 1)?;
                let (right_ty, right) = self.term(right, locals, depth + 1)?;
                same(right_ty, left_ty)?;
                let (ty, rule) = match op {
                    BinaryOp::Add
                    | BinaryOp::Sub
                    | BinaryOp::Mul
                    | BinaryOp::Div
                    | BinaryOp::Rem => {
                        same(left_ty, KernelType::I64)?;
                        (KernelType::I64, "arith")
                    }
                    BinaryOp::And | BinaryOp::Or => {
                        same(left_ty, KernelType::Bool)?;
                        (
                            KernelType::Bool,
                            if *op == BinaryOp::And { "and" } else { "or" },
                        )
                    }
                    BinaryOp::Eq | BinaryOp::Ne if left_ty == KernelType::Bool => {
                        return Ok((
                            KernelType::Bool,
                            format!("NamedHasType.cmpBool (by trivial) ({left}) ({right})"),
                        ));
                    }
                    BinaryOp::Eq
                    | BinaryOp::Ne
                    | BinaryOp::Lt
                    | BinaryOp::Le
                    | BinaryOp::Gt
                    | BinaryOp::Ge => {
                        same(left_ty, KernelType::I64)?;
                        (KernelType::Bool, "cmpInt")
                    }
                };
                (ty, rule, vec![left, right])
            }
            Term::If {
                condition,
                then_branch,
                else_branch,
            } => {
                let (condition_ty, condition) = self.term(condition, locals, depth + 1)?;
                same(condition_ty, KernelType::Bool)?;
                let (then_ty, then_branch) = self.term(then_branch, locals, depth + 1)?;
                let (else_ty, else_branch) = self.term(else_branch, locals, depth + 1)?;
                same(else_ty, then_ty)?;
                (then_ty, "ite", vec![condition, then_branch, else_branch])
            }
            Term::Let { bound, value, body } => {
                // The initializer sees the outer environment. A new binding is
                // in scope only for the body; retain shadowing semantics even
                // though the current real-source profile refuses shadowing.
                let (value_ty, value) = self.term(value, locals, depth + 1)?;
                locals.insert(0, (bound.clone(), value_ty));
                let body = self.term(body, locals, depth + 1);
                locals.remove(0);
                let (body_ty, body) = body?;
                (body_ty, "letIn", vec![value, body])
            }
            Term::Call { callee, args } => {
                let index = *self
                    .functions
                    .get(callee)
                    .ok_or(TypingError::MissingFunction)?;
                let function = &self.program.functions[index];
                if args.len() != function.params.len() {
                    return Err(TypingError::ArityMismatch);
                }
                let return_type = function.return_type;
                let mut proofs = Vec::with_capacity(args.len());
                for (argument, (_, expected)) in args.iter().zip(&function.params) {
                    let (actual, proof) = self.term(argument, locals, depth + 1)?;
                    same(actual, *expected)?;
                    proofs.push(proof);
                }
                let mut arguments = "NamedArgsHaveTypes.nil".to_owned();
                for proof in proofs.into_iter().rev() {
                    arguments = format!("NamedArgsHaveTypes.cons ({proof}) ({arguments})");
                }
                return Ok((
                    return_type,
                    format!(
                        "NamedHasType.call (i := {index}) (fd := {}) (by rfl) (by rfl) ({arguments})",
                        self.definitions[index]
                    ),
                ));
            }
        };
        let mut proof = format!("NamedHasType.{rule}");
        for premise in proofs {
            proof.push_str(&format!(" ({premise})"));
        }
        Ok((ty, proof))
    }
}

#[cfg(test)]
#[path = "typing/tests.rs"]
mod tests;
