use super::*;
use crate::kernel_zero::term::KernelFn;

fn id(index: usize) -> ValueId {
    ValueId::intrinsic_parameter("typing", index)
}

fn function(body: Term, return_type: KernelType) -> KernelFn {
    KernelFn {
        id: DeclarationId::new("entry"),
        params: vec![],
        return_type,
        body,
    }
}

fn check(functions: Vec<KernelFn>) -> Result<Vec<String>, TypingError> {
    let definitions = (0..functions.len())
        .map(|i| format!("fd{i}"))
        .collect::<Vec<_>>();
    derive(&KernelProgram { functions }, &definitions)
}

fn binary(op: BinaryOp, left: Term, right: Term) -> Term {
    Term::Binary(op, Box::new(left), Box::new(right))
}

#[test]
fn literals_unary_arithmetic_boolean_and_comparison_rules_are_distinct() {
    for op in [
        BinaryOp::Add,
        BinaryOp::Sub,
        BinaryOp::Mul,
        BinaryOp::Div,
        BinaryOp::Rem,
    ] {
        let proofs = check(vec![function(
            binary(op, Term::Int(1), Term::Int(0)),
            KernelType::I64,
        )])
        .unwrap();
        assert!(proofs[0].starts_with("NamedHasType.arith"));
    }
    for op in [
        BinaryOp::Eq,
        BinaryOp::Ne,
        BinaryOp::Lt,
        BinaryOp::Le,
        BinaryOp::Gt,
        BinaryOp::Ge,
    ] {
        let proofs = check(vec![function(
            binary(op, Term::Int(1), Term::Int(0)),
            KernelType::Bool,
        )])
        .unwrap();
        assert!(proofs[0].starts_with("NamedHasType.cmpInt"));
    }
    for op in [BinaryOp::Eq, BinaryOp::Ne] {
        let proofs = check(vec![function(
            binary(op, Term::Bool(true), Term::Bool(false)),
            KernelType::Bool,
        )])
        .unwrap();
        assert!(proofs[0].starts_with("NamedHasType.cmpBool"));
    }
    for (op, rule) in [(BinaryOp::And, "and"), (BinaryOp::Or, "or")] {
        let proofs = check(vec![function(
            binary(op, Term::Bool(true), Term::Bool(false)),
            KernelType::Bool,
        )])
        .unwrap();
        assert!(proofs[0].starts_with(&format!("NamedHasType.{rule}")));
    }
    for (op, value, ty, rule) in [
        (UnaryOp::Neg, Term::Int(i64::MIN), KernelType::I64, "neg"),
        (UnaryOp::Not, Term::Bool(false), KernelType::Bool, "not"),
    ] {
        let proofs = check(vec![function(Term::Unary(op, Box::new(value)), ty)]).unwrap();
        assert!(proofs[0].starts_with(&format!("NamedHasType.{rule}")));
    }
}

#[test]
fn malformed_operators_and_return_annotations_fail_closed() {
    for body in [
        binary(BinaryOp::Lt, Term::Bool(false), Term::Bool(true)),
        binary(BinaryOp::Add, Term::Bool(false), Term::Bool(true)),
        binary(BinaryOp::And, Term::Int(1), Term::Int(2)),
        binary(BinaryOp::Eq, Term::Int(1), Term::Bool(true)),
        Term::Unary(UnaryOp::Neg, Box::new(Term::Bool(true))),
        Term::Unary(UnaryOp::Not, Box::new(Term::Int(1))),
        Term::Int(7),
    ] {
        assert_eq!(
            check(vec![function(body, KernelType::Bool)]),
            Err(TypingError::TypeMismatch)
        );
    }
}

#[test]
fn condition_and_both_branches_must_type_even_when_dead() {
    let valid = Term::If {
        condition: Box::new(Term::Bool(true)),
        then_branch: Box::new(Term::Int(1)),
        else_branch: Box::new(Term::Int(2)),
    };
    assert!(
        check(vec![function(valid.clone(), KernelType::I64)]).unwrap()[0]
            .starts_with("NamedHasType.ite")
    );
    let Term::If {
        then_branch,
        else_branch,
        ..
    } = valid
    else {
        unreachable!()
    };
    assert_eq!(
        check(vec![function(
            Term::If {
                condition: Box::new(Term::Int(0)),
                then_branch,
                else_branch,
            },
            KernelType::I64
        )]),
        Err(TypingError::TypeMismatch)
    );
    assert_eq!(
        check(vec![function(
            Term::If {
                condition: Box::new(Term::Bool(true)),
                then_branch: Box::new(Term::Int(1)),
                else_branch: Box::new(Term::Bool(false)),
            },
            KernelType::I64
        )]),
        Err(TypingError::TypeMismatch)
    );
}

#[test]
fn let_initializer_uses_outer_scope_and_body_uses_nearest_binding() {
    let body = Term::Let {
        bound: id(0),
        value: Box::new(binary(BinaryOp::Eq, Term::Var(id(0)), Term::Int(0))),
        body: Box::new(Term::Var(id(0))),
    };
    let mut entry = function(body, KernelType::Bool);
    entry.params = vec![(id(0), KernelType::I64)];
    assert!(check(vec![entry.clone()]).unwrap()[0].starts_with("NamedHasType.letIn"));
    entry.params.clear();
    assert_eq!(check(vec![entry]), Err(TypingError::UnboundVariable));
}

#[test]
fn a_let_in_one_sibling_never_leaks_to_the_other() {
    let scoped = Term::Let {
        bound: id(0),
        value: Box::new(Term::Int(1)),
        body: Box::new(Term::Var(id(0))),
    };
    assert_eq!(
        check(vec![function(
            binary(BinaryOp::Add, scoped, Term::Var(id(0))),
            KernelType::I64
        )]),
        Err(TypingError::UnboundVariable)
    );
}

#[test]
fn call_lookup_arity_and_ordered_types_are_checked() {
    let mut callee = function(Term::Var(id(0)), KernelType::I64);
    callee.id = DeclarationId::new("callee");
    callee.params = vec![(id(0), KernelType::I64), (id(1), KernelType::Bool)];
    let call = |args| {
        function(
            Term::Call {
                callee: callee.id.clone(),
                args,
            },
            KernelType::I64,
        )
    };
    let valid = call(vec![Term::Int(9), Term::Bool(true)]);
    let proofs = check(vec![valid.clone(), callee.clone()]).unwrap();
    assert!(proofs[0].contains("(i := 1) (fd := fd1)"));
    assert!(proofs[0].contains("NamedArgsHaveTypes.cons (NamedHasType.intLit) (NamedArgsHaveTypes.cons (NamedHasType.boolLit)"));
    assert_eq!(check(vec![valid]), Err(TypingError::MissingFunction));
    assert_eq!(
        check(vec![call(vec![Term::Int(9)]), callee.clone()]),
        Err(TypingError::ArityMismatch)
    );
    assert_eq!(
        check(vec![
            call(vec![Term::Bool(true), Term::Int(9)]),
            callee.clone()
        ]),
        Err(TypingError::TypeMismatch)
    );
}

#[test]
fn complete_function_inventory_and_every_body_are_checked() {
    let entry = function(Term::Int(0), KernelType::I64);
    assert_eq!(
        check(vec![entry.clone(), entry.clone()]),
        Err(TypingError::DuplicateFunction)
    );
    let mut invalid = entry.clone();
    invalid.id = DeclarationId::new("unreachable");
    invalid.return_type = KernelType::Bool;
    assert_eq!(
        check(vec![entry.clone(), invalid]),
        Err(TypingError::TypeMismatch)
    );
    let mut duplicate_parameter = entry.clone();
    duplicate_parameter.params = vec![(id(0), KernelType::I64), (id(0), KernelType::Bool)];
    assert_eq!(
        check(vec![duplicate_parameter]),
        Err(TypingError::DuplicateParameter)
    );
    assert_eq!(
        derive(
            &KernelProgram {
                functions: vec![entry]
            },
            &[]
        ),
        Err(TypingError::DefinitionInventory)
    );
}

#[test]
fn typing_does_not_claim_termination_or_reject_typed_faults() {
    let recursive = function(
        Term::Call {
            callee: DeclarationId::new("entry"),
            args: vec![],
        },
        KernelType::I64,
    );
    assert!(check(vec![recursive]).is_ok());
    assert!(check(vec![function(
        binary(BinaryOp::Div, Term::Int(1), Term::Int(0)),
        KernelType::I64
    )])
    .is_ok());
}

#[test]
fn depth_and_signature_work_have_exact_limits() {
    let mut body = Term::Bool(true);
    for _ in 0..MAX_DEPTH {
        body = Term::Unary(UnaryOp::Not, Box::new(body));
    }
    assert!(check(vec![function(body.clone(), KernelType::Bool)]).is_ok());
    body = Term::Unary(UnaryOp::Not, Box::new(body));
    assert_eq!(
        check(vec![function(body, KernelType::Bool)]),
        Err(TypingError::Limit)
    );
    let mut entry = function(Term::Int(0), KernelType::I64);
    entry.params = (0..MAX_NODES - 1)
        .map(|i| (id(i), KernelType::I64))
        .collect();
    assert!(check(vec![entry.clone()]).is_ok());
    entry.params.push((id(MAX_NODES), KernelType::I64));
    assert_eq!(check(vec![entry]), Err(TypingError::Limit));
    let functions = (0..=MAX_FUNCTIONS)
        .map(|i| {
            let mut f = function(Term::Int(0), KernelType::I64);
            f.id = DeclarationId::new(format!("f{i}"));
            f
        })
        .collect();
    assert_eq!(check(functions), Err(TypingError::Limit));
}
