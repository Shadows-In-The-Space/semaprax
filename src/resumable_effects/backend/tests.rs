use std::path::Path;
use std::process::Command;

use crate::cleanup_plan::StatusCase;
use crate::conformance::NormalizedStatus;
use crate::hir::{self, ResolvedProgram};
use crate::interpreter::resumable::{resume_resumable_effect, run_resumable_effect, ResumableStep};
use crate::interpreter::ArgumentValue;
use crate::resumable_effects::lowering::{self, ResumablePlan, ResumableScalar};

use super::{resume, run, Backend, BackendStep};

fn program(type_name: &str, request: &str, result: &str) -> ResolvedProgram {
    let source = format!(
        r#"
module test.resumable_backend;
@id("app.ask")
fn ask(seed: {type_name}) -> {type_name}
    yields {type_name} -> {type_name}
{{
    let request = {request};
    let answer = yield request;
    {result}
}}
@id("app.main")
fn main() -> i64 {{ 0 }}
"#
    );
    let ast = crate::parse(&source, Path::new("resumable-backend.spx")).unwrap();
    hir::resolve(&ast).unwrap()
}

fn contract_program() -> ResolvedProgram {
    let source = r#"
module test.resumable_backend_contracts;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
    requires seed >= 0
    ensures result >= 0
{
    let answer = yield seed;
    answer
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let ast = crate::parse(source, Path::new("resumable-backend-contracts.spx")).unwrap();
    hir::resolve(&ast).unwrap()
}

fn plan(program: &ResolvedProgram) -> ResumablePlan {
    let function = program
        .functions
        .iter()
        .find(|function| function.id.as_str() == "app.ask")
        .unwrap();
    lowering::lower(program, function).unwrap()
}

fn require_tools() -> bool {
    let clang = Command::new("clang").arg("--version").output().is_ok();
    let node = Command::new("node").arg("--version").output().is_ok();
    if clang && node {
        true
    } else if std::env::var_os("SEMAPRAX_REQUIRE_RESUMABLE_BACKENDS").is_some() {
        panic!("SEMAPRAX_REQUIRE_RESUMABLE_BACKENDS requires both clang and node");
    } else {
        eprintln!("skipping resumable backend parity: clang or node unavailable");
        false
    }
}

fn require_clang() -> bool {
    if Command::new("clang").arg("--version").output().is_ok() {
        true
    } else if std::env::var_os("SEMAPRAX_REQUIRE_RESUMABLE_BACKENDS").is_some() {
        panic!("SEMAPRAX_REQUIRE_RESUMABLE_BACKENDS requires clang");
    } else {
        eprintln!("skipping resumable native parity: clang unavailable");
        false
    }
}

#[test]
fn native_o0_o2_and_core_wasm_preserve_signed_zero_bits() {
    if !require_tools() {
        return;
    }
    let cases = [
        (
            "f32",
            ResumableScalar::F32(0x8000_0000),
            ResumableScalar::F32(0x0000_0000),
        ),
        (
            "f64",
            ResumableScalar::F64(0x0000_0000_0000_0000),
            ResumableScalar::F64(0x8000_0000_0000_0000),
        ),
    ];
    for (type_name, request, answer) in cases {
        let program = program(type_name, "seed", "answer");
        let plan = plan(&program);
        for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
            let BackendStep::Suspended(suspension) =
                run(backend, &program, &plan, std::slice::from_ref(&request)).unwrap()
            else {
                panic!("start did not suspend");
            };
            assert_eq!(suspension.request(), &request);
            assert_eq!(
                resume(
                    backend,
                    &program,
                    &plan,
                    std::slice::from_ref(&request),
                    &suspension,
                    answer.clone(),
                )
                .unwrap(),
                BackendStep::Complete {
                    state: plan.complete.id.clone(),
                    result: answer.clone(),
                },
            );
        }
    }
}

#[test]
fn prefix_and_suffix_language_failures_match_interpreter_native_and_wasm() {
    if !require_tools() {
        return;
    }
    let expected = NormalizedStatus::arithmetic(StatusCase::AddOverflow);

    let prefix_program = program("i64", "seed + 1", "answer");
    let prefix_plan = plan(&prefix_program);
    let interpreted = run_resumable_effect(
        &prefix_program,
        "app.ask",
        &[ArgumentValue::Int(i64::MAX)],
        10_000,
    )
    .unwrap();
    assert_eq!(
        interpreted.step,
        ResumableStep::LanguageFailure(expected.clone())
    );
    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        assert_eq!(
            run(
                backend,
                &prefix_program,
                &prefix_plan,
                &[ResumableScalar::I64(i64::MAX)],
            )
            .unwrap(),
            BackendStep::LanguageFailure(expected.clone()),
        );
    }

    let suffix_program = program("i64", "seed", "answer + 1");
    let suffix_plan = plan(&suffix_program);
    let interpreted_start =
        run_resumable_effect(&suffix_program, "app.ask", &[ArgumentValue::Int(7)], 10_000).unwrap();
    let ResumableStep::Suspended {
        state,
        binding,
        request,
    } = interpreted_start.step
    else {
        panic!("interpreter start did not suspend");
    };
    let interpreted_resume = resume_resumable_effect(
        &suffix_program,
        "app.ask",
        &[ArgumentValue::Int(7)],
        &state,
        &binding,
        &request,
        &ArgumentValue::Int(i64::MAX),
        10_000,
    )
    .unwrap();
    assert_eq!(
        interpreted_resume.step,
        ResumableStep::LanguageFailure(expected.clone())
    );
    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        let BackendStep::Suspended(suspension) = run(
            backend,
            &suffix_program,
            &suffix_plan,
            &[ResumableScalar::I64(7)],
        )
        .unwrap() else {
            panic!("backend start did not suspend");
        };
        assert_eq!(
            resume(
                backend,
                &suffix_program,
                &suffix_plan,
                &[ResumableScalar::I64(7)],
                &suspension,
                ResumableScalar::I64(i64::MAX),
            )
            .unwrap(),
            BackendStep::LanguageFailure(expected.clone()),
        );
    }

    let contracts = contract_program();
    let contract_plan = plan(&contracts);
    let requires = NormalizedStatus::contract(crate::cleanup_plan::ContractPhase::Requires);
    let interpreted_requires =
        run_resumable_effect(&contracts, "app.ask", &[ArgumentValue::Int(-1)], 10_000).unwrap();
    assert_eq!(
        interpreted_requires.step,
        ResumableStep::LanguageFailure(requires.clone())
    );
    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        assert_eq!(
            run(
                backend,
                &contracts,
                &contract_plan,
                &[ResumableScalar::I64(-1)],
            )
            .unwrap(),
            BackendStep::LanguageFailure(requires.clone()),
        );
    }

    let interpreted_contract_start =
        run_resumable_effect(&contracts, "app.ask", &[ArgumentValue::Int(1)], 10_000).unwrap();
    let ResumableStep::Suspended {
        state,
        binding,
        request,
    } = interpreted_contract_start.step
    else {
        panic!("interpreter contract start did not suspend");
    };
    let ensures = NormalizedStatus::contract(crate::cleanup_plan::ContractPhase::Ensures);
    let interpreted_ensures = resume_resumable_effect(
        &contracts,
        "app.ask",
        &[ArgumentValue::Int(1)],
        &state,
        &binding,
        &request,
        &ArgumentValue::Int(-1),
        10_000,
    )
    .unwrap();
    assert_eq!(
        interpreted_ensures.step,
        ResumableStep::LanguageFailure(ensures.clone())
    );
    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        let BackendStep::Suspended(suspension) = run(
            backend,
            &contracts,
            &contract_plan,
            &[ResumableScalar::I64(1)],
        )
        .unwrap() else {
            panic!("backend contract start did not suspend");
        };
        assert_eq!(
            resume(
                backend,
                &contracts,
                &contract_plan,
                &[ResumableScalar::I64(1)],
                &suspension,
                ResumableScalar::I64(-1),
            )
            .unwrap(),
            BackendStep::LanguageFailure(ensures.clone()),
        );
    }
}

#[test]
fn suspension_binding_refuses_same_request_with_different_arguments_before_target_execution() {
    let program = program("i64", "7", "seed + answer");
    let plan = plan(&program);
    // No tool availability prerequisite: the binding refusal occurs before
    // either clang or node can be invoked.
    let suspension = super::BackendSuspension {
        state: plan.suspension.state.id.clone(),
        request: ResumableScalar::I64(7),
        binding: plan.suspension_binding(&[ResumableScalar::I64(11)]),
    };
    let error = resume(
        Backend::CoreWasm,
        &program,
        &plan,
        &[ResumableScalar::I64(12)],
        &suspension,
        ResumableScalar::I64(5),
    )
    .unwrap_err();
    assert_eq!(error.code, "SPX-F115");
}

#[test]
fn suspension_state_identity_is_checked_before_target_execution() {
    let program = program("i64", "seed", "answer");
    let plan = plan(&program);
    let suspension = super::BackendSuspension {
        state: plan.complete.id.clone(),
        request: ResumableScalar::I64(9),
        binding: plan.suspension_binding(&[ResumableScalar::I64(9)]),
    };
    let error = resume(
        Backend::NativeO0,
        &program,
        &plan,
        &[ResumableScalar::I64(9)],
        &suspension,
        ResumableScalar::I64(1),
    )
    .unwrap_err();
    assert_eq!(error.code, "SPX-F115");
}

#[test]
fn all_three_backends_detect_negative_zero_request_drift_by_bits() {
    if !require_tools() {
        return;
    }
    let program = program("f64", "seed", "answer");
    let plan = plan(&program);
    let argument = ResumableScalar::F64(0x8000_0000_0000_0000);
    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        let BackendStep::Suspended(mut suspension) =
            run(backend, &program, &plan, std::slice::from_ref(&argument)).unwrap()
        else {
            panic!("start did not suspend");
        };
        suspension.request = ResumableScalar::F64(0);
        let error = resume(
            backend,
            &program,
            &plan,
            std::slice::from_ref(&argument),
            &suspension,
            ResumableScalar::F64(0x3ff0_0000_0000_0000),
        )
        .unwrap_err();
        assert_eq!(error.code, "SPX-F114");
    }
}

#[test]
fn wrong_typed_resume_is_refused_before_target_execution() {
    let program = program("i64", "seed", "answer");
    let plan = plan(&program);
    let suspension = super::BackendSuspension {
        state: plan.suspension.state.id.clone(),
        request: ResumableScalar::I64(9),
        binding: plan.suspension_binding(&[ResumableScalar::I64(9)]),
    };
    let error = resume(
        Backend::NativeO2,
        &program,
        &plan,
        &[ResumableScalar::I64(9)],
        &suspension,
        ResumableScalar::Bool(true),
    )
    .unwrap_err();
    assert_eq!(error.code, "SPX-F113");
}

#[test]
fn usize_is_native_only_and_core_wasm_fails_closed() {
    let program = program("usize", "seed", "answer");
    let plan = plan(&program);
    let wasm = run(
        Backend::CoreWasm,
        &program,
        &plan,
        &[ResumableScalar::Usize(u64::MAX)],
    )
    .unwrap_err();
    assert_eq!(wasm.code, "SPX-W115");

    if !require_clang() {
        return;
    }
    for backend in [Backend::NativeO0, Backend::NativeO2] {
        let BackendStep::Suspended(suspension) = run(
            backend,
            &program,
            &plan,
            &[ResumableScalar::Usize(u64::MAX)],
        )
        .unwrap() else {
            panic!("start did not suspend");
        };
        assert_eq!(suspension.request(), &ResumableScalar::Usize(u64::MAX));
        assert_eq!(
            resume(
                backend,
                &program,
                &plan,
                &[ResumableScalar::Usize(u64::MAX)],
                &suspension,
                ResumableScalar::Usize(0x8000_0000_0000_0001),
            )
            .unwrap(),
            BackendStep::Complete {
                state: plan.complete.id.clone(),
                result: ResumableScalar::Usize(0x8000_0000_0000_0001),
            },
        );
    }
}
