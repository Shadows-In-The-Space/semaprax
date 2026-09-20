//! Translation from a real `ResolvedFunction` to a Kernel-0 [`Term`].
//!
//! [`translate_program`] adds bounded admission and independent HIR replay
//! before translating the acyclic scalar fragment. [`BoundTranslation`]
//! additionally binds exact source and selected entry to the resulting term.
//! Every branch below that
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

use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::hir::{
    DeclarationId, OwnershipMode, ResolvedExpr, ResolvedExprKind, ResolvedFunction,
    ResolvedProgram, ResolvedStatement, ResolvedType,
};

use super::term::{KernelFn, KernelProgram, KernelType, Term};

const MAX_SOURCE_BYTES: usize = 64 * 1024;
const MAX_FUNCTIONS: usize = 64;
const MAX_NODES: usize = 8192;
const MAX_DEPTH: usize = 128;

/// Internal proof-profile refusals, not new compiler diagnostics or admission rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    Capacity,
    InvalidSource,
    InvalidHir,
    MissingFunction,
    Effects,
    Contracts,
    NonScalar,
    Ownership,
    Recursion,
    UnsupportedControlFlow,
    GenericCall,
    BindingMismatch,
}

/// Private, authority-free evidence. Replay derives the entire term again from
/// exact source bytes; a digest is an association, never a correctness proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundTranslation {
    source_digest: [u8; 32],
    entry: DeclarationId,
    term_digest: [u8; 32],
    program: KernelProgram,
}

impl BoundTranslation {
    pub(crate) fn derive(source: &str, entry: &DeclarationId) -> Result<Self, Refusal> {
        if source.len() > MAX_SOURCE_BYTES {
            return Err(Refusal::Capacity);
        }
        let ast = crate::parse(source, "kernel-zero-bound-source.spx")
            .map_err(|_| Refusal::InvalidSource)?;
        let hir = crate::hir::resolve(&ast).map_err(|_| Refusal::InvalidHir)?;
        let program = translate_checked(&hir, entry)?;
        let mut hash = Sha256::new();
        hash.update(b"semaprax.kernel-zero.source.v1\0");
        hash.update(source.as_bytes());
        Ok(Self {
            source_digest: hash.finalize().into(),
            entry: entry.clone(),
            term_digest: term_digest(&program),
            program,
        })
    }

    pub(crate) fn replay(
        &self,
        source: &str,
        entry: &DeclarationId,
    ) -> Result<&KernelProgram, Refusal> {
        let expected = Self::derive(source, entry)?;
        if self != &expected {
            return Err(Refusal::BindingMismatch);
        }
        Ok(&self.program)
    }
}

fn translate_checked(
    program: &ResolvedProgram,
    entry: &DeclarationId,
) -> Result<KernelProgram, Refusal> {
    // Check bounded structure before calling recursive HIR replay or allocating
    // terms. Memoization visits a shared callee once; the grey set detects cycles.
    let mut admission = Admission {
        program,
        visiting: HashSet::new(),
        done: HashSet::new(),
        nodes: 0,
    };
    admission.function(entry, 0)?;
    crate::hir::validate(program).map_err(|_| Refusal::InvalidHir)?;
    Ok(translate_admitted(program, entry))
}

struct Admission<'a> {
    program: &'a ResolvedProgram,
    visiting: HashSet<DeclarationId>,
    done: HashSet<DeclarationId>,
    nodes: usize,
}

impl Admission<'_> {
    fn function(&mut self, id: &DeclarationId, depth: usize) -> Result<(), Refusal> {
        if depth >= MAX_DEPTH {
            return Err(Refusal::Capacity);
        }
        if self.visiting.contains(id) {
            return Err(Refusal::Recursion);
        }
        if self.done.contains(id) {
            return Ok(());
        }
        if self.done.len() + self.visiting.len() >= MAX_FUNCTIONS {
            return Err(Refusal::Capacity);
        }
        let function = self
            .program
            .functions
            .iter()
            .find(|f| &f.id == id)
            .ok_or(Refusal::MissingFunction)?;
        if !function.effects.is_empty() || function.yields.is_some() {
            return Err(Refusal::Effects);
        }
        if !function.requires.is_empty() || !function.ensures.is_empty() {
            return Err(Refusal::Contracts);
        }
        if !scalar(&function.return_type) || function.params.iter().any(|p| !scalar(&p.ty)) {
            return Err(Refusal::NonScalar);
        }
        if function
            .params
            .iter()
            .any(|p| p.ownership != OwnershipMode::Value)
        {
            return Err(Refusal::Ownership);
        }
        self.visiting.insert(id.clone());
        self.expression(&function.body, depth)?;
        self.visiting.remove(id);
        self.done.insert(id.clone());
        Ok(())
    }

    fn expression(&mut self, expr: &ResolvedExpr, depth: usize) -> Result<(), Refusal> {
        if depth >= MAX_DEPTH || self.nodes >= MAX_NODES {
            return Err(Refusal::Capacity);
        }
        self.nodes += 1;
        if !scalar(&expr.ty) {
            return Err(Refusal::NonScalar);
        }
        if expr.ownership != OwnershipMode::Value {
            return Err(Refusal::Ownership);
        }
        match &expr.kind {
            ResolvedExprKind::Int(_) | ResolvedExprKind::Bool(_) => Ok(()),
            ResolvedExprKind::Place(place) if place.projections.is_empty() => Ok(()),
            ResolvedExprKind::Unary { value, .. } => self.expression(value, depth + 1),
            ResolvedExprKind::Binary { left, right, .. } => {
                self.expression(left, depth + 1)?;
                self.expression(right, depth + 1)
            }
            ResolvedExprKind::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.expression(condition, depth + 1)?;
                self.expression(then_branch, depth + 1)?;
                self.expression(else_branch, depth + 1)
            }
            ResolvedExprKind::Block { statements, tail } => {
                if statements.len() >= MAX_DEPTH.saturating_sub(depth) {
                    return Err(Refusal::Capacity);
                }
                for (index, statement) in statements.iter().enumerate() {
                    let ResolvedStatement::Let {
                        mutable: false,
                        value,
                        ..
                    } = statement
                    else {
                        return Err(Refusal::UnsupportedControlFlow);
                    };
                    // Each lowered let adds a term node and a nesting level.
                    if self.nodes >= MAX_NODES {
                        return Err(Refusal::Capacity);
                    }
                    self.nodes += 1;
                    self.expression(value, depth + index + 1)?;
                }
                self.expression(tail, depth + statements.len() + 1)
            }
            ResolvedExprKind::Call {
                callee,
                type_arguments,
                instance,
                args,
            } => {
                if !type_arguments.is_empty() || instance.is_some() {
                    return Err(Refusal::GenericCall);
                }
                for arg in args {
                    self.expression(arg, depth + 1)?;
                }
                self.function(callee, depth + 1)
            }
            _ => Err(Refusal::UnsupportedControlFlow),
        }
    }
}

fn scalar(ty: &ResolvedType) -> bool {
    matches!(ty, ResolvedType::I64 | ResolvedType::Bool)
}

/// Translates the reifying subgraph reachable from `entry` (by `Call`) into
/// a [`KernelProgram`]. Returns `None` on a profile, capacity, or HIR replay
/// refusal. These internal restrictions never narrow compiler admission.
pub(crate) fn translate_program(
    program: &ResolvedProgram,
    entry: &DeclarationId,
) -> Option<KernelProgram> {
    translate_checked(program, entry).ok()
}

fn translate_admitted(program: &ResolvedProgram, entry: &DeclarationId) -> KernelProgram {
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
    functions.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    KernelProgram { functions }
}

/// Prefix tags and length-prefixed UTF-8 identities avoid Debug-format or
/// delimiter ambiguity. Function order is canonical; expression/call order is authored.
fn term_digest(program: &KernelProgram) -> [u8; 32] {
    fn text(hash: &mut Sha256, value: &str) {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    fn term(hash: &mut Sha256, value: &Term) {
        use crate::ast::{BinaryOp, UnaryOp};
        match value {
            Term::Int(n) => {
                hash.update([0]);
                hash.update(n.to_le_bytes());
            }
            Term::Bool(b) => hash.update([1, u8::from(*b)]),
            Term::Var(id) => {
                hash.update([2]);
                text(hash, id.as_str());
            }
            Term::Unary(op, value) => {
                hash.update([
                    3,
                    match op {
                        UnaryOp::Neg => 0,
                        UnaryOp::Not => 1,
                    },
                ]);
                term(hash, value);
            }
            Term::Binary(op, left, right) => {
                hash.update([
                    4,
                    match op {
                        BinaryOp::Add => 0,
                        BinaryOp::Sub => 1,
                        BinaryOp::Mul => 2,
                        BinaryOp::Div => 3,
                        BinaryOp::Rem => 4,
                        BinaryOp::Eq => 5,
                        BinaryOp::Ne => 6,
                        BinaryOp::Lt => 7,
                        BinaryOp::Le => 8,
                        BinaryOp::Gt => 9,
                        BinaryOp::Ge => 10,
                        BinaryOp::And => 11,
                        BinaryOp::Or => 12,
                    },
                ]);
                term(hash, left);
                term(hash, right);
            }
            Term::If {
                condition,
                then_branch,
                else_branch,
            } => {
                hash.update([5]);
                term(hash, condition);
                term(hash, then_branch);
                term(hash, else_branch);
            }
            Term::Let { bound, value, body } => {
                hash.update([6]);
                text(hash, bound.as_str());
                term(hash, value);
                term(hash, body);
            }
            Term::Call { callee, args } => {
                hash.update([7]);
                text(hash, callee.as_str());
                hash.update((args.len() as u64).to_le_bytes());
                for arg in args {
                    term(hash, arg);
                }
            }
        }
    }
    fn ty(hash: &mut Sha256, ty: KernelType) {
        hash.update([match ty {
            KernelType::I64 => 0,
            KernelType::Bool => 1,
        }]);
    }
    let mut hash = Sha256::new();
    hash.update(b"semaprax.kernel-zero.term.v1\0");
    hash.update((program.functions.len() as u64).to_le_bytes());
    for function in &program.functions {
        text(&mut hash, function.id.as_str());
        hash.update((function.params.len() as u64).to_le_bytes());
        for (id, param_ty) in &function.params {
            text(&mut hash, id.as_str());
            ty(&mut hash, *param_ty);
        }
        ty(&mut hash, function.return_type);
        term(&mut hash, &function.body);
    }
    hash.finalize().into()
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
    use super::{
        term_digest, translate_checked, translate_program, Admission, BoundTranslation, Refusal,
        MAX_DEPTH, MAX_FUNCTIONS, MAX_NODES, MAX_SOURCE_BYTES,
    };
    use crate::hir;
    use crate::kernel_zero::eval::eval_program;
    use crate::kernel_zero::value::Value;
    use std::collections::HashSet;

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

    const BOUND_SOURCE: &str = r#"module test.bound;
@id("test.subtract")
fn subtract(left: i64, right: i64) -> i64 { left - right }
@id("app.main")
fn main() -> i64 { let answer = subtract(50, 8); if answer == 42 { answer } else { 1 / 0 } }
"#;

    #[test]
    fn bound_translation_replays_and_evaluates_the_exact_source() {
        let entry = hir::DeclarationId::new("app.main");
        let binding = BoundTranslation::derive(BOUND_SOURCE, &entry).unwrap();
        assert_eq!(
            binding,
            BoundTranslation::derive(BOUND_SOURCE, &entry).unwrap()
        );
        let program = binding.replay(BOUND_SOURCE, &entry).unwrap();
        assert_eq!(
            eval_program(program, program.function(&entry).unwrap(), &[]),
            Ok(Value::Int(42))
        );
        assert!(program
            .functions
            .windows(2)
            .all(|pair| pair[0].id.as_str() < pair[1].id.as_str()));
    }

    #[test]
    fn binding_refuses_source_entry_digest_and_reminted_term_drift() {
        let entry = hir::DeclarationId::new("app.main");
        let original = BoundTranslation::derive(BOUND_SOURCE, &entry).unwrap();
        for source in [
            format!("{BOUND_SOURCE} "),
            BOUND_SOURCE.replace("50, 8", "51, 8"),
        ] {
            assert_eq!(
                original.replay(&source, &entry),
                Err(Refusal::BindingMismatch)
            );
        }
        assert_eq!(
            original.replay(BOUND_SOURCE, &hir::DeclarationId::new("test.subtract")),
            Err(Refusal::BindingMismatch)
        );
        for change in 0..4 {
            let mut forged = original.clone();
            match change {
                0 => forged.source_digest[0] ^= 1,
                1 => forged.term_digest[0] ^= 1,
                2 => forged.entry = hir::DeclarationId::new("test.subtract"),
                _ => {
                    forged.program.functions[0].body = super::Term::Int(43);
                    forged.term_digest = term_digest(&forged.program);
                }
            }
            assert_eq!(
                forged.replay(BOUND_SOURCE, &entry),
                Err(Refusal::BindingMismatch)
            );
        }
    }

    #[test]
    fn checked_translation_refuses_invalid_hir_and_a_forged_call_cycle() {
        let entry = hir::DeclarationId::new("app.main");
        let mut program = resolve(BOUND_SOURCE);
        let main = program
            .functions
            .iter_mut()
            .find(|f| f.id == entry)
            .unwrap();
        main.body.kind = hir::ResolvedExprKind::Bool(true); // retains its i64 annotation
        assert_eq!(
            translate_checked(&program, &entry),
            Err(Refusal::InvalidHir)
        );
        let main = program
            .functions
            .iter_mut()
            .find(|f| f.id == entry)
            .unwrap();
        main.body.kind = hir::ResolvedExprKind::Call {
            callee: entry.clone(),
            type_arguments: Vec::new(),
            instance: None,
            args: Vec::new(),
        };
        assert_eq!(translate_checked(&program, &entry), Err(Refusal::Recursion));
        assert_eq!(
            translate_checked(&program, &hir::DeclarationId::new("missing")),
            Err(Refusal::MissingFunction)
        );
    }

    #[test]
    fn bound_translation_reports_profile_refusals_without_dropping_semantics() {
        let entry = hir::DeclarationId::new("app.main");
        let cases = [
            ("module test.refusal; permit { clock.read } @id(\"app.main\") fn main() -> i64 uses { clock.read } { 1 }", Refusal::Effects),
            ("module test.refusal; @id(\"app.main\") fn main() -> i64 requires true { 1 }", Refusal::Contracts),
            ("module test.refusal; @id(\"test.pair\") record Pair { @id(\"test.pair.value\") value: i64, } @id(\"app.main\") fn main() -> i64 { let pair = Pair { value: 1 }; pair.value }", Refusal::NonScalar),
            ("module test.refusal; @id(\"app.main\") fn main() -> i64 { let mut value = 1; value = 2; value }", Refusal::UnsupportedControlFlow),
            ("module test.refusal; @id(\"test.ping\") fn ping(value: i64) -> i64 { if value <= 0 { 0 } else { pong(value - 1) } } @id(\"test.pong\") fn pong(value: i64) -> i64 { if value <= 0 { 0 } else { ping(value - 1) } } @id(\"app.main\") fn main() -> i64 { ping(3) }", Refusal::Recursion),
        ];
        for (source, expected) in cases {
            // The compiler admits each fixture; refusal belongs to the proof profile.
            let _ = resolve(source);
            assert_eq!(
                BoundTranslation::derive(source, &entry),
                Err(expected),
                "{source}"
            );
        }
    }

    #[test]
    fn exact_source_capacity_is_checked_before_parsing() {
        let entry = hir::DeclarationId::new("app.main");
        let mut source = BOUND_SOURCE.to_owned();
        source.push_str(&" ".repeat(MAX_SOURCE_BYTES - source.len()));
        assert!(BoundTranslation::derive(&source, &entry).is_ok());
        source.push(' ');
        assert_eq!(
            BoundTranslation::derive(&source, &entry),
            Err(Refusal::Capacity)
        );
        assert_eq!(
            BoundTranslation::derive(&"!".repeat(MAX_SOURCE_BYTES + 1), &entry),
            Err(Refusal::Capacity)
        );
    }

    #[test]
    fn structural_budget_checks_exact_limits_before_recursive_work() {
        let program = resolve(BOUND_SOURCE);
        let scalar = hir::ResolvedExpr {
            kind: hir::ResolvedExprKind::Int(1),
            ..program.functions[0].body.clone()
        };
        let mut admission = Admission {
            program: &program,
            visiting: HashSet::new(),
            done: HashSet::new(),
            nodes: 0,
        };
        assert_eq!(admission.expression(&scalar, MAX_DEPTH - 1), Ok(()));
        assert_eq!(
            admission.expression(&scalar, MAX_DEPTH),
            Err(Refusal::Capacity)
        );
        admission.nodes = MAX_NODES - 1;
        assert_eq!(admission.expression(&scalar, 0), Ok(()));
        assert_eq!(admission.expression(&scalar, 0), Err(Refusal::Capacity));
        admission.done = (0..MAX_FUNCTIONS)
            .map(|i| hir::DeclarationId::new(format!("done.{i}")))
            .collect();
        assert_eq!(
            admission.function(&hir::DeclarationId::new("app.main"), 0),
            Err(Refusal::Capacity)
        );
        admission.done.clear();
        admission.nodes = 0;
        // A call encountered just inside the nesting limit must not reset depth.
        let call = hir::ResolvedExpr {
            kind: hir::ResolvedExprKind::Call {
                callee: hir::DeclarationId::new("app.main"),
                type_arguments: Vec::new(),
                instance: None,
                args: Vec::new(),
            },
            ..scalar
        };
        assert_eq!(
            admission.expression(&call, MAX_DEPTH - 1),
            Err(Refusal::Capacity)
        );
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
