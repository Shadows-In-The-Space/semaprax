use std::path::Path;
use std::process::Command;

use crate::cleanup_plan::StatusCase;
use crate::conformance::NormalizedStatus;
use crate::hir::{self, ResolvedProgram};
use crate::interpreter::resumable::{
    checkpoint, resume_resumable_effect, run_resumable_effect, run_sequential_resumable_effect,
    ResumableStep, SequentialResumableStep,
};
use crate::interpreter::ArgumentValue;
use crate::resumable_effects::lowering::{self, ResumableScalar, SequentialResumablePlan};

use super::{resume, resume_sequential, run, Backend, BackendStep};

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

fn distinct_response_assignment_program() -> ResolvedProgram {
    let source = r#"
module test.resumable_backend_assignment;
@id("app.ask")
fn ask(seed: i64) -> bool
    yields i64 -> bool
{
    let mut answer = false;
    answer = yield seed + 1;
    answer
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let ast = crate::parse(
        source,
        Path::new("resumable-backend-distinct-response-assignment.spx"),
    )
    .unwrap();
    hir::resolve(&ast).unwrap()
}

fn sequential_program() -> ResolvedProgram {
    let source = r#"
module test.sequential_resumable_backend;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
{
    let first = yield seed + 1;
    let second = yield first + 2;
    first + second
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let ast = crate::parse(source, Path::new("sequential-resumable-backend.spx")).unwrap();
    hir::resolve(&ast).unwrap()
}

fn bounded_eight_site_program() -> ResolvedProgram {
    let source = r#"
module test.bounded_eight_site_resumable_backend;
@id("app.ask")
fn ask() -> i64
    yields i64 -> i64
{
    let a0 = yield 4;
    let a1 = yield a0 + 1;
    let a2 = yield a1 + 1;
    let a3 = yield a2 + 1;
    let a4 = yield a3 + 1;
    let a5 = yield a4 + 1;
    let a6 = yield a5 + 1;
    let a7 = yield a6 + 1;
    a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let ast = crate::parse(
        source,
        Path::new("bounded-eight-site-resumable-backend.spx"),
    )
    .unwrap();
    hir::resolve(&ast).unwrap()
}

fn sequential_failure_program(
    second_request: &str,
    result: &str,
    ensures: &str,
) -> ResolvedProgram {
    let source = format!(
        r#"
module test.sequential_resumable_backend_failure;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
    {ensures}
{{
    let first = yield seed;
    let second = yield {second_request};
    {result}
}}
@id("app.main")
fn main() -> i64 {{ 0 }}
"#
    );
    let ast = crate::parse(
        &source,
        Path::new("sequential-resumable-backend-failure.spx"),
    )
    .unwrap();
    hir::resolve(&ast).unwrap()
}

fn plan(program: &ResolvedProgram) -> SequentialResumablePlan {
    let function = program
        .functions
        .iter()
        .find(|function| function.id.as_str() == "app.ask")
        .unwrap();
    lowering::lower_sequential(program, function).unwrap()
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
fn direct_assignment_uses_the_response_type_across_interpreter_native_and_wasm() {
    if !require_tools() {
        return;
    }
    let program = distinct_response_assignment_program();
    let plan = plan(&program);
    let arguments = [ResumableScalar::I64(41)];
    let interpreted =
        run_resumable_effect(&program, "app.ask", &[ArgumentValue::Int(41)], 10_000).unwrap();
    let ResumableStep::Suspended {
        state,
        binding,
        request,
    } = interpreted.step
    else {
        panic!("interpreter assignment start did not suspend")
    };
    assert_eq!(request, ArgumentValue::Int(42));
    assert!(matches!(
        resume_resumable_effect(
            &program,
            "app.ask",
            &[ArgumentValue::Int(41)],
            &state,
            &binding,
            &request,
            &ArgumentValue::Bool(true),
            10_000,
        )
        .unwrap()
        .step,
        ResumableStep::Completed {
            result: ArgumentValue::Bool(true),
            ..
        }
    ));

    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        let BackendStep::Suspended(suspension) = run(backend, &program, &plan, &arguments).unwrap()
        else {
            panic!("backend assignment start did not suspend")
        };
        assert_eq!(suspension.request(), &ResumableScalar::I64(42));
        assert_eq!(
            resume(
                backend,
                &program,
                &plan,
                &arguments,
                &suspension,
                ResumableScalar::Bool(true),
            )
            .unwrap(),
            BackendStep::Complete {
                state: plan.complete.id.clone(),
                result: ResumableScalar::Bool(true),
            }
        );
    }
}

#[test]
fn two_yields_match_across_native_o0_o2_and_core_wasm() {
    if !require_tools() {
        return;
    }
    let program = sequential_program();
    let plan = plan(&program);
    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        let BackendStep::SequentialSuspended(first) =
            run(backend, &program, &plan, &[ResumableScalar::I64(4)]).unwrap()
        else {
            panic!("two-site backend start did not suspend sequentially")
        };
        assert_eq!(first.request(), &ResumableScalar::I64(5));
        let BackendStep::SequentialSuspended(second) = resume_sequential(
            backend,
            &program,
            &plan,
            &[ResumableScalar::I64(4)],
            &first,
            ResumableScalar::I64(10),
        )
        .unwrap() else {
            panic!("first backend answer did not park the second request")
        };
        assert_eq!(second.request(), &ResumableScalar::I64(12));
        assert_ne!(second.state(), first.state());
        assert_eq!(
            resume_sequential(
                backend,
                &program,
                &plan,
                &[ResumableScalar::I64(4)],
                &second,
                ResumableScalar::I64(20),
            )
            .unwrap(),
            BackendStep::Complete {
                state: plan.complete.id.clone(),
                result: ResumableScalar::I64(30),
            }
        );
    }
}

#[test]
fn recovered_sequential_checkpoint_stays_in_parity_with_every_backend() {
    if !require_tools() {
        return;
    }
    let program = sequential_program();
    let plan = plan(&program);
    let arguments = [ArgumentValue::Int(4)];
    let interpreted =
        run_sequential_resumable_effect(&program, "app.ask", &arguments, 10_000).unwrap();
    let SequentialResumableStep::Suspended { continuation } = interpreted.step else {
        panic!("checkpoint parity interpreter start did not suspend")
    };
    let bytes = checkpoint::encode("app.ask", &continuation).unwrap();
    let recovered = checkpoint::decode(&program, "app.ask", &arguments, &bytes).unwrap();
    let interpreted = crate::interpreter::resumable::resume_sequential_resumable_effect(
        &program,
        "app.ask",
        &arguments,
        &recovered,
        &ArgumentValue::Int(10),
        10_000,
    )
    .unwrap();
    let SequentialResumableStep::Suspended { continuation } = interpreted.step else {
        panic!("recovered checkpoint did not park the second interpreter request")
    };
    assert_eq!(continuation.request(), &ArgumentValue::Int(12));

    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        let BackendStep::SequentialSuspended(first) =
            run(backend, &program, &plan, &[ResumableScalar::I64(4)]).unwrap()
        else {
            panic!("checkpoint parity backend start did not suspend")
        };
        let BackendStep::SequentialSuspended(second) = resume_sequential(
            backend,
            &program,
            &plan,
            &[ResumableScalar::I64(4)],
            &first,
            ResumableScalar::I64(10),
        )
        .unwrap() else {
            panic!("checkpoint parity backend did not park its second request")
        };
        assert_eq!(second.request(), &ResumableScalar::I64(12));
        assert_eq!(
            resume_sequential(
                backend,
                &program,
                &plan,
                &[ResumableScalar::I64(4)],
                &second,
                ResumableScalar::I64(20),
            )
            .unwrap(),
            BackendStep::Complete {
                state: plan.complete.id.clone(),
                result: ResumableScalar::I64(30),
            }
        );
    }
}

#[test]
fn eight_sites_replay_full_history_across_interpreter_and_every_backend() {
    if !require_tools() {
        return;
    }
    let program = bounded_eight_site_program();
    let plan = plan(&program);
    let arguments = [];

    let interpreted = run_sequential_resumable_effect(&program, "app.ask", &[], 10_000).unwrap();
    let SequentialResumableStep::Suspended {
        continuation: mut interpreted,
    } = interpreted.step
    else {
        panic!("eight-site interpreter start did not suspend")
    };
    assert_eq!(interpreted.request(), &ArgumentValue::Int(4));
    for answer in [10_i64, 20, 30, 40, 50, 60, 70] {
        let resumed = crate::interpreter::resumable::resume_sequential_resumable_effect(
            &program,
            "app.ask",
            &[],
            &interpreted,
            &ArgumentValue::Int(answer),
            10_000,
        )
        .unwrap();
        let SequentialResumableStep::Suspended { continuation } = resumed.step else {
            panic!("eight-site interpreter completed before its final site")
        };
        assert_eq!(continuation.request(), &ArgumentValue::Int(answer + 1));
        interpreted = continuation;
    }
    assert!(matches!(
        crate::interpreter::resumable::resume_sequential_resumable_effect(
            &program,
            "app.ask",
            &[],
            &interpreted,
            &ArgumentValue::Int(80),
            10_000,
        )
        .unwrap()
        .step,
        SequentialResumableStep::Completed {
            result: ArgumentValue::Int(360),
            ..
        }
    ));

    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        let BackendStep::SequentialSuspended(mut continuation) =
            run(backend, &program, &plan, &arguments).unwrap()
        else {
            panic!("eight-site backend start did not suspend")
        };
        assert_eq!(continuation.request(), &ResumableScalar::I64(4));
        for answer in [10_i64, 20, 30, 40, 50, 60, 70] {
            let resumed = resume_sequential(
                backend,
                &program,
                &plan,
                &arguments,
                &continuation,
                ResumableScalar::I64(answer),
            )
            .unwrap();
            let BackendStep::SequentialSuspended(next) = resumed else {
                panic!("eight-site backend completed before its final site")
            };
            assert_eq!(next.request(), &ResumableScalar::I64(answer + 1));
            continuation = next;
            if answer == 30 {
                let mut changed_history = continuation.clone();
                changed_history.history[1].request = ResumableScalar::I64(999);
                assert_eq!(
                    resume_sequential(
                        backend,
                        &program,
                        &plan,
                        &arguments,
                        &changed_history,
                        ResumableScalar::I64(40),
                    )
                    .unwrap_err()
                    .code,
                    "SPX-F114"
                );
            }
        }
        assert_eq!(
            resume_sequential(
                backend,
                &program,
                &plan,
                &arguments,
                &continuation,
                ResumableScalar::I64(80),
            )
            .unwrap(),
            BackendStep::Complete {
                state: plan.complete.id.clone(),
                result: ResumableScalar::I64(360),
            }
        );
    }
}

#[test]
fn sequential_intermediate_final_and_postcondition_failures_match_every_backend() {
    if !require_tools() {
        return;
    }
    let overflow = NormalizedStatus::arithmetic(StatusCase::AddOverflow);
    let ensures = NormalizedStatus::contract(crate::cleanup_plan::ContractPhase::Ensures);

    let intermediate = sequential_failure_program("first + 1", "second", "");
    let intermediate_plan = plan(&intermediate);
    let interpreted =
        run_sequential_resumable_effect(&intermediate, "app.ask", &[ArgumentValue::Int(7)], 10_000)
            .unwrap();
    let SequentialResumableStep::Suspended {
        continuation: interpreted,
    } = interpreted.step
    else {
        panic!("intermediate-failure interpreter start did not suspend")
    };
    assert_eq!(
        crate::interpreter::resumable::resume_sequential_resumable_effect(
            &intermediate,
            "app.ask",
            &[ArgumentValue::Int(7)],
            &interpreted,
            &ArgumentValue::Int(i64::MAX),
            10_000,
        )
        .unwrap()
        .step,
        SequentialResumableStep::LanguageFailure(overflow.clone())
    );
    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        let BackendStep::SequentialSuspended(first) = run(
            backend,
            &intermediate,
            &intermediate_plan,
            &[ResumableScalar::I64(7)],
        )
        .unwrap() else {
            panic!("intermediate-failure backend start did not suspend")
        };
        assert_eq!(
            resume_sequential(
                backend,
                &intermediate,
                &intermediate_plan,
                &[ResumableScalar::I64(7)],
                &first,
                ResumableScalar::I64(i64::MAX),
            )
            .unwrap(),
            BackendStep::LanguageFailure(overflow.clone())
        );
    }

    let final_failure = sequential_failure_program("first", "second + 1", "");
    let final_plan = plan(&final_failure);
    let interpreted = run_sequential_resumable_effect(
        &final_failure,
        "app.ask",
        &[ArgumentValue::Int(7)],
        10_000,
    )
    .unwrap();
    let SequentialResumableStep::Suspended {
        continuation: first,
    } = interpreted.step
    else {
        panic!("final-failure interpreter start did not suspend")
    };
    let interpreted = crate::interpreter::resumable::resume_sequential_resumable_effect(
        &final_failure,
        "app.ask",
        &[ArgumentValue::Int(7)],
        &first,
        &ArgumentValue::Int(1),
        10_000,
    )
    .unwrap();
    let SequentialResumableStep::Suspended {
        continuation: second,
    } = interpreted.step
    else {
        panic!("final-failure interpreter did not reach its second site")
    };
    assert_eq!(
        crate::interpreter::resumable::resume_sequential_resumable_effect(
            &final_failure,
            "app.ask",
            &[ArgumentValue::Int(7)],
            &second,
            &ArgumentValue::Int(i64::MAX),
            10_000,
        )
        .unwrap()
        .step,
        SequentialResumableStep::LanguageFailure(overflow.clone())
    );
    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        let BackendStep::SequentialSuspended(first) = run(
            backend,
            &final_failure,
            &final_plan,
            &[ResumableScalar::I64(7)],
        )
        .unwrap() else {
            panic!("final-failure backend start did not suspend")
        };
        let BackendStep::SequentialSuspended(second) = resume_sequential(
            backend,
            &final_failure,
            &final_plan,
            &[ResumableScalar::I64(7)],
            &first,
            ResumableScalar::I64(1),
        )
        .unwrap() else {
            panic!("final-failure backend did not reach its second site")
        };
        assert_eq!(
            resume_sequential(
                backend,
                &final_failure,
                &final_plan,
                &[ResumableScalar::I64(7)],
                &second,
                ResumableScalar::I64(i64::MAX),
            )
            .unwrap(),
            BackendStep::LanguageFailure(overflow.clone())
        );
    }

    let postcondition = sequential_failure_program("first", "second", "ensures result >= 0");
    let postcondition_plan = plan(&postcondition);
    let interpreted = run_sequential_resumable_effect(
        &postcondition,
        "app.ask",
        &[ArgumentValue::Int(7)],
        10_000,
    )
    .unwrap();
    let SequentialResumableStep::Suspended {
        continuation: first,
    } = interpreted.step
    else {
        panic!("postcondition interpreter start did not suspend")
    };
    let interpreted = crate::interpreter::resumable::resume_sequential_resumable_effect(
        &postcondition,
        "app.ask",
        &[ArgumentValue::Int(7)],
        &first,
        &ArgumentValue::Int(1),
        10_000,
    )
    .unwrap();
    let SequentialResumableStep::Suspended {
        continuation: second,
    } = interpreted.step
    else {
        panic!("postcondition interpreter did not reach its second site")
    };
    assert_eq!(
        crate::interpreter::resumable::resume_sequential_resumable_effect(
            &postcondition,
            "app.ask",
            &[ArgumentValue::Int(7)],
            &second,
            &ArgumentValue::Int(-1),
            10_000,
        )
        .unwrap()
        .step,
        SequentialResumableStep::LanguageFailure(ensures.clone())
    );
    for backend in [Backend::NativeO0, Backend::NativeO2, Backend::CoreWasm] {
        let BackendStep::SequentialSuspended(first) = run(
            backend,
            &postcondition,
            &postcondition_plan,
            &[ResumableScalar::I64(7)],
        )
        .unwrap() else {
            panic!("postcondition backend start did not suspend")
        };
        let BackendStep::SequentialSuspended(second) = resume_sequential(
            backend,
            &postcondition,
            &postcondition_plan,
            &[ResumableScalar::I64(7)],
            &first,
            ResumableScalar::I64(1),
        )
        .unwrap() else {
            panic!("postcondition backend did not reach its second site")
        };
        assert_eq!(
            resume_sequential(
                backend,
                &postcondition,
                &postcondition_plan,
                &[ResumableScalar::I64(7)],
                &second,
                ResumableScalar::I64(-1),
            )
            .unwrap(),
            BackendStep::LanguageFailure(ensures.clone())
        );
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
        state: plan.suspensions[0].state.id.clone(),
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
        state: plan.suspensions[0].state.id.clone(),
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
