//! Concrete, exact-source normalization witnesses for the Kernel-0 calculus.
//!
//! The Lean model proves that a closed, typed term carrying a valid weighted
//! call certificate normalizes within its initial potential. The Rust proof
//! harness already derives and replays those weights, but previously stopped
//! before connecting them to an actual sequence of Kernel-0 reductions. This
//! module narrows that finite bridge: it derives the exact source-bound term,
//! independently checks its typing, performs textbook small steps, rechecks
//! the type after every step, and requires the replayed weighted potential to
//! decrease strictly. It is executable evidence for concrete inputs, not a
//! universal correspondence proof, an external-kernel judgment, or authority.

use crate::ast::BinaryOp;
use crate::hir::{DeclarationId, ValueId};

use super::super::eval::{eval_binary, eval_unary};
use super::super::reify::{BoundTranslation, Refusal as TranslationRefusal};
use super::super::term::{KernelProgram, KernelType, Term};
use super::super::value::{Fault, Value};
use super::super::weights::{self, WeightError, Weights};
use super::typing::{self, TypingError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Refusal {
    Translation,
    Weight,
    Typing,
    ArgumentCount,
    ArgumentType,
    NonDecreasingPotential,
    FuelExhausted,
}

impl From<TranslationRefusal> for Refusal {
    fn from(_: TranslationRefusal) -> Self {
        Self::Translation
    }
}

impl From<WeightError> for Refusal {
    fn from(_: WeightError) -> Self {
        Self::Weight
    }
}

impl From<TypingError> for Refusal {
    fn from(_: TypingError) -> Self {
        Self::Typing
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Value(Value),
    Fault(Fault),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutionWitness {
    arguments: Vec<Value>,
    outcome: Outcome,
    reductions: u64,
    initial_potential: u64,
    terminal_potential: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundNormalizer {
    translation: BoundTranslation,
    entry: DeclarationId,
    weights: Weights,
    fuel: u64,
    return_type: KernelType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CorpusAudit {
    pub(super) programs: usize,
    pub(super) witnesses: usize,
    pub(super) values: usize,
    pub(super) faults: usize,
    pub(super) longest_trace: u64,
}

impl BoundNormalizer {
    fn derive(source: &str, entry: &DeclarationId) -> Result<Self, Refusal> {
        let translation = BoundTranslation::derive(source, entry)?;
        let program = translation.replay(source, entry)?;
        let definitions = (0..program.functions.len())
            .map(|index| format!("normalizationDefinition{index}"))
            .collect::<Vec<_>>();
        typing::derive(program, &definitions)?;
        let weights = weights::derive(program)?;
        weights::verify(program, &weights)?;
        let function = program.function(entry).ok_or(Refusal::Translation)?;
        let fuel = weights::value_call_fuel(program, &weights, entry)?;
        let return_type = function.return_type;
        Ok(Self {
            translation,
            entry: entry.clone(),
            weights,
            fuel,
            return_type,
        })
    }

    fn execute(
        &self,
        source: &str,
        entry: &DeclarationId,
        arguments: &[Value],
    ) -> Result<ExecutionWitness, Refusal> {
        if entry != &self.entry {
            return Err(Refusal::Translation);
        }
        let program = self.translation.replay(source, entry)?;
        weights::verify(program, &self.weights)?;
        let expected_weights = weights::derive(program)?;
        if expected_weights != self.weights
            || weights::value_call_fuel(program, &expected_weights, entry)? != self.fuel
        {
            return Err(Refusal::Weight);
        }
        let function = program.function(entry).ok_or(Refusal::Translation)?;
        if arguments.len() != function.params.len() {
            return Err(Refusal::ArgumentCount);
        }
        for (argument, (_, expected)) in arguments.iter().zip(&function.params) {
            if value_type(*argument) != *expected {
                return Err(Refusal::ArgumentType);
            }
        }

        let mut term = Term::Call {
            callee: entry.clone(),
            args: arguments.iter().copied().map(value_term).collect(),
        };
        typing::check_closed_term(program, &term, self.return_type)?;
        let initial_potential = weights::term_potential(program, &self.weights, &term)?;
        if initial_potential != self.fuel {
            return Err(Refusal::Weight);
        }
        let mut potential = initial_potential;
        let mut reductions = 0;
        loop {
            match step(program, &term)? {
                Step::Value(value) => {
                    return Ok(ExecutionWitness {
                        arguments: arguments.to_vec(),
                        outcome: Outcome::Value(value),
                        reductions,
                        initial_potential,
                        terminal_potential: potential,
                    });
                }
                Step::Fault(fault) => {
                    return Ok(ExecutionWitness {
                        arguments: arguments.to_vec(),
                        outcome: Outcome::Fault(fault),
                        reductions,
                        initial_potential,
                        terminal_potential: potential,
                    });
                }
                Step::Reduced(next) => {
                    reductions = reductions.checked_add(1).ok_or(Refusal::FuelExhausted)?;
                    if reductions > self.fuel {
                        return Err(Refusal::FuelExhausted);
                    }
                    typing::check_closed_term(program, &next, self.return_type)?;
                    let next_potential = weights::term_potential(program, &self.weights, &next)?;
                    if next_potential >= potential {
                        return Err(Refusal::NonDecreasingPotential);
                    }
                    term = next;
                    potential = next_potential;
                }
            }
        }
    }

    fn replay(
        &self,
        source: &str,
        entry: &DeclarationId,
        witness: &ExecutionWitness,
    ) -> Result<(), Refusal> {
        let expected = Self::derive(source, entry)?;
        if &expected != self {
            return Err(Refusal::Translation);
        }
        let replayed = self.execute(source, entry, &witness.arguments)?;
        if &replayed != witness {
            return Err(Refusal::Translation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Step {
    Reduced(Term),
    Value(Value),
    Fault(Fault),
}

fn value_type(value: Value) -> KernelType {
    match value {
        Value::Int(_) => KernelType::I64,
        Value::Bool(_) => KernelType::Bool,
    }
}

fn value_term(value: Value) -> Term {
    match value {
        Value::Int(value) => Term::Int(value),
        Value::Bool(value) => Term::Bool(value),
    }
}

fn term_value(term: &Term) -> Option<Value> {
    match term {
        Term::Int(value) => Some(Value::Int(*value)),
        Term::Bool(value) => Some(Value::Bool(*value)),
        _ => None,
    }
}

fn reduce_child(
    program: &KernelProgram,
    child: &Term,
    rebuild: impl FnOnce(Term) -> Term,
) -> Result<Step, Refusal> {
    match step(program, child)? {
        Step::Reduced(next) => Ok(Step::Reduced(rebuild(next))),
        Step::Fault(fault) => Ok(Step::Fault(fault)),
        Step::Value(_) => unreachable!("a non-value child reduced to Value without being a value"),
    }
}

fn step(program: &KernelProgram, term: &Term) -> Result<Step, Refusal> {
    match term {
        Term::Int(value) => Ok(Step::Value(Value::Int(*value))),
        Term::Bool(value) => Ok(Step::Value(Value::Bool(*value))),
        Term::Var(_) => Err(Refusal::Typing),
        Term::Unary(operator, operand) => {
            if let Some(value) = term_value(operand) {
                return Ok(match eval_unary(*operator, value) {
                    Ok(value) => Step::Reduced(value_term(value)),
                    Err(fault) => Step::Fault(fault),
                });
            }
            reduce_child(program, operand, |next| {
                Term::Unary(*operator, Box::new(next))
            })
        }
        Term::Binary(BinaryOp::And, left, right) => {
            if let Some(value) = term_value(left) {
                return match value {
                    Value::Bool(false) => Ok(Step::Reduced(Term::Bool(false))),
                    Value::Bool(true) => Ok(Step::Reduced((**right).clone())),
                    Value::Int(_) => Err(Refusal::Typing),
                };
            }
            reduce_child(program, left, |next| {
                Term::Binary(BinaryOp::And, Box::new(next), right.clone())
            })
        }
        Term::Binary(BinaryOp::Or, left, right) => {
            if let Some(value) = term_value(left) {
                return match value {
                    Value::Bool(true) => Ok(Step::Reduced(Term::Bool(true))),
                    Value::Bool(false) => Ok(Step::Reduced((**right).clone())),
                    Value::Int(_) => Err(Refusal::Typing),
                };
            }
            reduce_child(program, left, |next| {
                Term::Binary(BinaryOp::Or, Box::new(next), right.clone())
            })
        }
        Term::Binary(operator, left, right) => {
            let Some(left_value) = term_value(left) else {
                return reduce_child(program, left, |next| {
                    Term::Binary(*operator, Box::new(next), right.clone())
                });
            };
            let Some(right_value) = term_value(right) else {
                return reduce_child(program, right, |next| {
                    Term::Binary(*operator, left.clone(), Box::new(next))
                });
            };
            Ok(match eval_binary(*operator, left_value, right_value) {
                Ok(value) => Step::Reduced(value_term(value)),
                Err(fault) => Step::Fault(fault),
            })
        }
        Term::If {
            condition,
            then_branch,
            else_branch,
        } => {
            if let Some(value) = term_value(condition) {
                return match value {
                    Value::Bool(true) => Ok(Step::Reduced((**then_branch).clone())),
                    Value::Bool(false) => Ok(Step::Reduced((**else_branch).clone())),
                    Value::Int(_) => Err(Refusal::Typing),
                };
            }
            reduce_child(program, condition, |next| Term::If {
                condition: Box::new(next),
                then_branch: then_branch.clone(),
                else_branch: else_branch.clone(),
            })
        }
        Term::Let { bound, value, body } => {
            if let Some(value) = term_value(value) {
                return Ok(Step::Reduced(substitute(body, bound, value)));
            }
            reduce_child(program, value, |next| Term::Let {
                bound: bound.clone(),
                value: Box::new(next),
                body: body.clone(),
            })
        }
        Term::Call { callee, args } => {
            for (index, argument) in args.iter().enumerate() {
                if term_value(argument).is_none() {
                    return match step(program, argument)? {
                        Step::Reduced(next) => {
                            let mut next_args = args.clone();
                            next_args[index] = next;
                            Ok(Step::Reduced(Term::Call {
                                callee: callee.clone(),
                                args: next_args,
                            }))
                        }
                        Step::Fault(fault) => Ok(Step::Fault(fault)),
                        Step::Value(_) => unreachable!(
                            "a non-value call argument reduced to Value without being a value"
                        ),
                    };
                }
            }
            let function = program.function(callee).ok_or(Refusal::Typing)?;
            if args.len() != function.params.len() {
                return Err(Refusal::Typing);
            }
            let mut body = function.body.clone();
            for ((parameter, _), argument) in function.params.iter().zip(args) {
                let value = term_value(argument).ok_or(Refusal::Typing)?;
                body = substitute(&body, parameter, value);
            }
            Ok(Step::Reduced(body))
        }
    }
}

fn substitute(term: &Term, target: &ValueId, replacement: Value) -> Term {
    match term {
        Term::Int(_) | Term::Bool(_) => term.clone(),
        Term::Var(id) if id == target => value_term(replacement),
        Term::Var(_) => term.clone(),
        Term::Unary(operator, value) => {
            Term::Unary(*operator, Box::new(substitute(value, target, replacement)))
        }
        Term::Binary(operator, left, right) => Term::Binary(
            *operator,
            Box::new(substitute(left, target, replacement)),
            Box::new(substitute(right, target, replacement)),
        ),
        Term::If {
            condition,
            then_branch,
            else_branch,
        } => Term::If {
            condition: Box::new(substitute(condition, target, replacement)),
            then_branch: Box::new(substitute(then_branch, target, replacement)),
            else_branch: Box::new(substitute(else_branch, target, replacement)),
        },
        Term::Let { bound, value, body } => Term::Let {
            bound: bound.clone(),
            value: Box::new(substitute(value, target, replacement)),
            body: if bound == target {
                body.clone()
            } else {
                Box::new(substitute(body, target, replacement))
            },
        },
        Term::Call { callee, args } => Term::Call {
            callee: callee.clone(),
            args: args
                .iter()
                .map(|argument| substitute(argument, target, replacement))
                .collect(),
        },
    }
}

pub(super) fn audit_generated_corpora() -> Result<CorpusAudit, Refusal> {
    let programs = crate::kernel_zero::corpus::generated_corpus()
        .into_iter()
        .chain(crate::kernel_zero::corpus::adversarial_fault_corpus())
        .chain(crate::kernel_zero::corpus::adversarial_structure_corpus())
        .collect::<Vec<_>>();
    let mut audit = CorpusAudit {
        programs: programs.len(),
        witnesses: 0,
        values: 0,
        faults: 0,
        longest_trace: 0,
    };
    for generated in programs {
        let entry = DeclarationId::new(&generated.entry_id);
        let normalizer = BoundNormalizer::derive(&generated.source, &entry)?;
        for arguments in generated.samples {
            let witness = normalizer.execute(&generated.source, &entry, &arguments)?;
            if witness.reductions > witness.initial_potential
                || witness.terminal_potential > witness.initial_potential
            {
                return Err(Refusal::NonDecreasingPotential);
            }
            normalizer.replay(&generated.source, &entry, &witness)?;
            audit.witnesses += 1;
            audit.longest_trace = audit.longest_trace.max(witness.reductions);
            match witness.outcome {
                Outcome::Value(_) => audit.values += 1,
                Outcome::Fault(_) => audit.faults += 1,
            }
        }
    }
    Ok(audit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = r#"module test.normalization;

@id("test.add")
fn add(left: i64, right: i64) -> i64 { left + right }

@id("app.entry")
fn entry(run: bool, value: i64) -> i64
{
    if run { add(value, 2) } else { 1 / 0 }
}

@id("app.main")
fn main() -> i64 { 0 }
"#;

    #[test]
    fn exact_source_witness_replays_value_and_fault_traces() {
        let entry = DeclarationId::new("app.entry");
        let normalizer = BoundNormalizer::derive(SOURCE, &entry).unwrap();
        let value = normalizer
            .execute(SOURCE, &entry, &[Value::Bool(true), Value::Int(40)])
            .unwrap();
        assert_eq!(value.outcome, Outcome::Value(Value::Int(42)));
        assert!(value.reductions >= 4);
        assert!(value.terminal_potential < value.initial_potential);
        normalizer.replay(SOURCE, &entry, &value).unwrap();

        let fault = normalizer
            .execute(SOURCE, &entry, &[Value::Bool(false), Value::Int(40)])
            .unwrap();
        assert_eq!(fault.outcome, Outcome::Fault(Fault::DivisionByZero));
        assert!(fault.reductions > 0);
        normalizer.replay(SOURCE, &entry, &fault).unwrap();
    }

    #[test]
    fn source_entry_argument_and_weight_drift_fail_closed() {
        let entry = DeclarationId::new("app.entry");
        let normalizer = BoundNormalizer::derive(SOURCE, &entry).unwrap();
        assert_eq!(
            normalizer.execute(
                &SOURCE.replace("left + right", "left - right"),
                &entry,
                &[Value::Bool(true), Value::Int(40)]
            ),
            Err(Refusal::Translation)
        );
        assert_eq!(
            normalizer.execute(SOURCE, &DeclarationId::new("test.add"), &[]),
            Err(Refusal::Translation)
        );
        assert_eq!(
            normalizer.execute(SOURCE, &entry, &[Value::Bool(true)]),
            Err(Refusal::ArgumentCount)
        );
        assert_eq!(
            normalizer.execute(SOURCE, &entry, &[Value::Int(1), Value::Int(40)]),
            Err(Refusal::ArgumentType)
        );

        let mut forged = normalizer;
        forged.weights.insert(entry.clone(), 1);
        assert_eq!(
            forged.execute(SOURCE, &entry, &[Value::Bool(true), Value::Int(40)]),
            Err(Refusal::Weight)
        );

        let normalizer = BoundNormalizer::derive(SOURCE, &entry).unwrap();
        let mut inflated = normalizer;
        *inflated.weights.get_mut(&entry).unwrap() += 1;
        inflated.fuel += 1;
        assert_eq!(
            inflated.execute(SOURCE, &entry, &[Value::Bool(true), Value::Int(40)]),
            Err(Refusal::Weight)
        );
    }

    #[test]
    fn generated_fault_and_structural_corpora_have_typed_descending_traces() {
        let audit = audit_generated_corpora().unwrap();
        assert_eq!(audit.programs, 74);
        assert!(
            audit.witnesses >= 700,
            "the normalization corpus became vacuous"
        );
        assert!(
            audit.values > 100,
            "successful traces disappeared from the corpus"
        );
        assert!(
            audit.faults > 100,
            "fault traces disappeared from the corpus"
        );
        assert!(
            audit.longest_trace >= 40,
            "the deep-call witness disappeared"
        );
    }
}
