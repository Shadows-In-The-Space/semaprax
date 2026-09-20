use super::*;
use std::path::Path;

const SOURCE: &str = r#"
module test.sequential_lowering;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
    requires seed >= 0
    ensures result >= 0
{
    let mut running = seed;
    let first = yield { running = running + 1; running };
    running = yield first + running;
    yield running + first
}
@id("app.main")
fn main() -> i64 { 0 }
"#;

fn program(source: &str) -> ResolvedProgram {
    let ast = crate::parse(source, Path::new("sequential-lowering.spx")).unwrap();
    hir::resolve(&ast).unwrap()
}

fn selected(program: &ResolvedProgram) -> &ResolvedFunction {
    program
        .functions
        .iter()
        .find(|function| function.id.as_str() == "app.ask")
        .unwrap()
}

#[test]
fn sequential_projections_have_ordered_sites_answer_parameters_and_contracts() {
    let program = program(SOURCE);
    let plan = lower_sequential(&program, selected(&program)).unwrap();
    assert_eq!(
        plan,
        lower_sequential(&program, selected(&program)).unwrap()
    );
    assert_eq!(plan.suspensions.len(), 3);
    assert_eq!(plan.resumes.len(), 3);
    assert!(matches!(
        plan.suspensions[1].position,
        ResumableYieldPosition::Statement {
            kind: ResumableStatementKind::Assign,
            ..
        }
    ));
    assert_eq!(plan.suspensions[2].position, ResumableYieldPosition::Tail);
    let start = plan.start_program(&program).unwrap();
    assert_eq!(selected(&start).requires.len(), 1);
    assert!(selected(&start).ensures.is_empty());
    for index in 0..3 {
        let projected = plan.resume_program_at(&program, index).unwrap();
        hir::validate(&projected).unwrap();
        let function = selected(&projected);
        assert_eq!(function.params.len(), index + 2);
        assert!(function.requires.is_empty());
        assert_eq!(function.ensures.len(), usize::from(index == 2));
        assert_eq!(
            plan.suspension_index(&plan.suspensions[index].state.id),
            Some(index)
        );
        let mut pending = vec![&function.body];
        while let Some(expression) = pending.pop() {
            assert!(!matches!(expression.kind, ResolvedExprKind::Yield { .. }));
            hir::push_resolved_expression_children_in_authored_order(expression, &mut pending);
        }
        // Every answered request remains evaluated, including its mutation.
        let ResolvedExprKind::Block { statements, .. } = &function.body.kind else {
            panic!()
        };
        let ResolvedExprKind::Block {
            statements: request,
            ..
        } = &statements[1].value().kind
        else {
            panic!()
        };
        assert_eq!(request.len(), 1);
        let ResolvedExprKind::Block {
            statements: mutation,
            ..
        } = &request[0].value().kind
        else {
            panic!()
        };
        assert!(matches!(mutation[0], ResolvedStatement::Assign { .. }));
    }
    assert_eq!(plan.suspension_index(&plan.complete.id), None);
    assert_eq!(
        plan.resume_program_at(&program, 3).unwrap_err().code,
        INVALID_RESUMABLE_PLAN
    );
}

#[test]
fn sequential_binding_commits_history_site_and_exact_scalar_bits() {
    let program = program(SOURCE);
    let plan = lower_sequential(&program, selected(&program)).unwrap();
    let arguments = [ResumableScalar::I64(1)];
    let positive = [ResumableScalar::F64(0.0f64.to_bits())];
    let negative = [ResumableScalar::F64((-0.0f64).to_bits())];
    assert_ne!(
        plan.suspension_binding_at(1, &arguments, &positive)
            .unwrap(),
        plan.suspension_binding_at(1, &arguments, &negative)
            .unwrap()
    );
    assert_ne!(
        plan.suspension_binding_at(0, &arguments, &[]).unwrap(),
        plan.suspension_binding_at(1, &arguments, &positive)
            .unwrap()
    );
    assert!(plan.suspension_binding_at(1, &arguments, &[]).is_err());
    assert!(plan.suspension_binding_at(3, &arguments, &[]).is_err());
    let mut forged = plan.clone();
    forged.suspensions.swap(0, 1);
    assert_eq!(
        forged.start_program(&program).unwrap_err().code,
        INVALID_RESUMABLE_PLAN
    );
    let mut forged = plan.clone();
    forged.resumes.swap(0, 1);
    assert_eq!(
        forged.start_program(&program).unwrap_err().code,
        INVALID_RESUMABLE_PLAN
    );
}

#[test]
fn eight_yields_are_admitted_and_every_projection_validates() {
    let mut source = String::from(
        "module test.eight_yields;\n@id(\"app.ask\")\nfn ask(seed: i64) -> i64 yields i64 -> i64 {\n",
    );
    for index in 0..8 {
        source.push_str(&format!("let answer{index} = yield seed + {index};\n"));
    }
    source.push_str("answer7\n}\n@id(\"app.main\")\nfn main() -> i64 { 0 }\n");
    let program = program(&source);
    let plan = lower_sequential(&program, selected(&program)).unwrap();
    assert_eq!(plan.suspensions.len(), MAX_RESUMABLE_YIELDS);
    hir::validate(&plan.start_program(&program).unwrap()).unwrap();
    for index in 0..MAX_RESUMABLE_YIELDS {
        hir::validate(&plan.resume_program_at(&program, index).unwrap()).unwrap();
    }
}

#[test]
fn intermediate_request_and_final_result_types_are_distinct() {
    let source = r#"
module test.sequential_types;
@id("app.ask")
fn ask(seed: i64) -> bool yields i64 -> bool {
    let first = yield seed;
    let second = yield if first { seed + 1 } else { seed + 2 };
    first && second
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let program = program(source);
    let plan = lower_sequential(&program, selected(&program)).unwrap();
    let intermediate = plan.resume_program_at(&program, 0).unwrap();
    assert_eq!(selected(&intermediate).return_type, ResolvedType::I64);
    assert_eq!(selected(&intermediate).params[1].ty, ResolvedType::Bool);
    let final_projection = plan.resume_program_at(&program, 1).unwrap();
    assert_eq!(selected(&final_projection).return_type, ResolvedType::Bool);
    assert_eq!(selected(&final_projection).params[2].ty, ResolvedType::Bool);
}

#[test]
fn lower_rejects_a_forged_ninth_or_nested_yield() {
    let mut program = program(SOURCE);
    let function = program
        .functions
        .iter_mut()
        .find(|function| function.id.as_str() == "app.ask")
        .unwrap();
    let ResolvedExprKind::Block { statements, .. } = &mut function.body.kind else {
        panic!()
    };
    let repeated = statements[1].clone();
    for _ in 0..6 {
        statements.push(repeated.clone());
    }
    let error = lower_sequential(&program, selected(&program)).unwrap_err();
    assert_eq!(error.code, INVALID_RESUMABLE_PLAN);
    assert!(error.message.contains("between 1 and 8 yields"));

    let mut program = self::program(SOURCE);
    let function = program
        .functions
        .iter_mut()
        .find(|function| function.id.as_str() == "app.ask")
        .unwrap();
    let ResolvedExprKind::Block { statements, tail } = &mut function.body.kind else {
        panic!()
    };
    let ResolvedExprKind::Yield { request } = &mut statements[1].value_mut().kind else {
        panic!()
    };
    *request = tail.clone();
    let error = lower_sequential(&program, selected(&program)).unwrap_err();
    assert_eq!(error.code, INVALID_RESUMABLE_PLAN);
}
