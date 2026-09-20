//! Resumable Effects v1 (issue #204): the interpreter suspend/resume lane.
//!
//! Every test here drives real `.spx` source through parse -> resolve ->
//! evaluate, so a regression in any of those layers reddens these, not only
//! a regression in this module.

use super::*;
use crate::hir;
use std::path::Path;

const MAX_STEPS: usize = 10_000;

/// The canonical slice program: one scalar parameter, one top-level
/// `yield`, and a suffix that uses the resumed value.
const ASK: &str = r#"
module test.resumable_effects_interpreter;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
{
    let answer = yield seed + 1;
    answer * 2
}
@id("app.main")
fn main() -> i64 { 0 }
"#;

fn resolved(source: &str) -> hir::ResolvedProgram {
    let program = crate::parse(source, Path::new("resumable-effects-interpreter.spx"))
        .expect("the slice source parses");
    hir::resolve(&program).expect("the slice source resolves")
}

fn suspension(
    program: &hir::ResolvedProgram,
    arguments: &[ArgumentValue],
) -> (ResumableStateId, ResumableSuspensionBinding, ArgumentValue) {
    match run_resumable_effect(program, "app.ask", arguments, MAX_STEPS)
        .unwrap()
        .step
    {
        ResumableStep::Suspended {
            state,
            binding,
            request,
        } => (state, binding, request),
        other => panic!("expected suspension, got {other:?}"),
    }
}

#[test]
fn a_fresh_invocation_suspends_at_its_yield_with_the_computed_request() {
    let program = resolved(ASK);
    let evaluated =
        run_resumable_effect(&program, "app.ask", &[ArgumentValue::Int(41)], MAX_STEPS).unwrap();
    // `seed + 1` is the request: the prefix really ran, it was not skipped.
    let ResumableStep::Suspended {
        state,
        binding,
        request,
    } = evaluated.step
    else {
        panic!("fresh invocation did not suspend")
    };
    assert_eq!(request, ArgumentValue::Int(42));
    assert!(state.as_str().contains("|suspended|"));
    assert_ne!(binding.as_bytes(), &[0; 32]);
    assert!(evaluated.steps_used > 0);
    assert_eq!(evaluated.max_steps, MAX_STEPS);
}

#[test]
fn resuming_substitutes_the_answer_at_the_yield_and_runs_the_suffix() {
    let program = resolved(ASK);
    let (state, binding, request) = suspension(&program, &[ArgumentValue::Int(41)]);
    let evaluated = resume_resumable_effect(
        &program,
        "app.ask",
        &[ArgumentValue::Int(41)],
        &state,
        &binding,
        &request,
        &ArgumentValue::Int(10),
        MAX_STEPS,
    )
    .unwrap();
    // 10 * 2 -- the suffix ran with the supplied answer, not with the
    // request and not with the seed.
    let ResumableStep::Completed {
        state: completed,
        result,
    } = &evaluated.step
    else {
        panic!("resume did not complete")
    };
    assert_eq!(*result, ArgumentValue::Int(20));
    assert!(completed.as_str().contains("|complete"));
    // Negative control: the suffix is genuinely a function of the answer.
    let other = resume_resumable_effect(
        &program,
        "app.ask",
        &[ArgumentValue::Int(41)],
        &state,
        &binding,
        &request,
        &ArgumentValue::Int(11),
        MAX_STEPS,
    )
    .unwrap();
    assert!(matches!(
        other.step,
        ResumableStep::Completed {
            result: ArgumentValue::Int(22),
            ..
        }
    ));
    assert_ne!(other.step, evaluated.step);
}

#[test]
fn a_resume_presenting_a_request_the_replayed_prefix_does_not_recompute_is_refused() {
    let program = resolved(ASK);
    let (state, binding, _) = suspension(&program, &[ArgumentValue::Int(41)]);
    // The genuine suspension for seed 41 recorded request 42. Presenting 99
    // is drift: the prefix recomputes 42 and the resume fails closed.
    let refused = resume_resumable_effect(
        &program,
        "app.ask",
        &[ArgumentValue::Int(41)],
        &state,
        &binding,
        &ArgumentValue::Int(99),
        &ArgumentValue::Int(10),
        MAX_STEPS,
    )
    .unwrap_err();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].code, "SPX-F114");
    assert!(refused[0].message.contains("different request"));
}

#[test]
fn a_resume_presenting_a_suspension_under_different_arguments_is_refused_before_replay() {
    let program = resolved(ASK);
    let (state, binding, request) = suspension(&program, &[ArgumentValue::Int(41)]);
    // The binding rejects the other invocation before request replay.
    let refused = resume_resumable_effect(
        &program,
        "app.ask",
        &[ArgumentValue::Int(7)],
        &state,
        &binding,
        &request,
        &ArgumentValue::Int(10),
        MAX_STEPS,
    )
    .unwrap_err();
    assert_eq!(refused[0].code, "SPX-F115");
}

#[test]
fn an_answer_of_the_wrong_type_is_refused_before_the_program_is_entered() {
    let program = resolved(ASK);
    let (state, binding, request) = suspension(&program, &[ArgumentValue::Int(41)]);
    for wrong in [
        ArgumentValue::Bool(true),
        ArgumentValue::Int32(10),
        ArgumentValue::Usize(10),
        ArgumentValue::BorrowedStr("ten".to_owned()),
    ] {
        let refused = resume_resumable_effect(
            &program,
            "app.ask",
            &[ArgumentValue::Int(41)],
            &state,
            &binding,
            &request,
            &wrong,
            MAX_STEPS,
        )
        .unwrap_err();
        assert_eq!(refused[0].code, "SPX-F113", "{wrong:?}");
        assert!(refused[0].message.contains("answer"), "{wrong:?}");
    }
}

#[test]
fn a_recorded_request_of_the_wrong_type_is_refused_the_same_way() {
    let program = resolved(ASK);
    let (state, binding, _) = suspension(&program, &[ArgumentValue::Int(41)]);
    let refused = resume_resumable_effect(
        &program,
        "app.ask",
        &[ArgumentValue::Int(41)],
        &state,
        &binding,
        &ArgumentValue::Bool(true),
        &ArgumentValue::Int(10),
        MAX_STEPS,
    )
    .unwrap_err();
    assert_eq!(refused[0].code, "SPX-F113");
    assert!(refused[0].message.contains("request"));
}

#[test]
fn an_argument_of_the_wrong_type_is_refused_before_anything_runs() {
    let program = resolved(ASK);
    let refused =
        run_resumable_effect(&program, "app.ask", &[ArgumentValue::Bool(true)], MAX_STEPS)
            .unwrap_err();
    assert_eq!(refused[0].code, "SPX-F103");
    let arity = run_resumable_effect(&program, "app.ask", &[], MAX_STEPS).unwrap_err();
    assert_eq!(arity[0].code, "SPX-F103");
    assert!(arity[0].message.contains("1 argument(s)"));
}

#[test]
fn a_function_that_cannot_suspend_is_refused_by_this_lane() {
    let program = resolved(ASK);
    let refused = run_resumable_effect(&program, "app.main", &[], MAX_STEPS).unwrap_err();
    assert_eq!(refused[0].code, "SPX-F102");
    assert!(refused[0].message.contains("declares no `yields` clause"));
    let absent = run_resumable_effect(&program, "app.absent", &[], MAX_STEPS).unwrap_err();
    assert_eq!(absent[0].code, "SPX-F102");
}

#[test]
fn max_steps_is_bounded_and_exhaustion_is_reported_rather_than_looping() {
    let program = resolved(ASK);
    assert_eq!(
        run_resumable_effect(&program, "app.ask", &[ArgumentValue::Int(41)], 0).unwrap_err()[0]
            .code,
        "SPX-F101"
    );
    let exhausted =
        run_resumable_effect(&program, "app.ask", &[ArgumentValue::Int(41)], 2).unwrap();
    assert_eq!(exhausted.step, ResumableStep::FuelExhausted);
}

#[test]
fn every_ordinary_interpreter_lane_still_refuses_a_yield_outright() {
    // `Resumption::Refused` is the default every other evaluator carries, so
    // a `yield` reaching one of them is a guard refusal, never a suspension.
    let mut state = Resumption::Refused;
    let refused = settle_yield(&mut state, Value::Int(1)).unwrap_err();
    let Flow::Guard(detail) = refused else {
        panic!("an ordinary lane must refuse a yield");
    };
    assert_eq!(detail, "`yield` is not yet evaluated by the interpreter");
}

#[test]
fn a_suspension_grants_no_authority_and_dispatches_nothing() {
    // The slice refuses `uses` effects (`SPX-T302`), so a suspending
    // function has no host boundary at all to cross; this pins that the
    // refusal is real rather than merely documented.
    let source = r#"
module test.resumable_effects_effectful;

permit { clock.read }

@id("app.ask")
fn ask(seed: i64) -> i64
    uses { clock.read }
    yields i64 -> i64
{
    let answer = yield seed + 1;
    answer * 2
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let program =
        crate::parse(source, Path::new("resumable-effects-effectful.spx")).expect("it parses");
    let refused = hir::resolve(&program).unwrap_err();
    assert!(
        refused.iter().any(|error| error.code == "SPX-T302"),
        "{refused:?}"
    );
}

#[test]
fn the_backends_that_cannot_lower_a_suspension_still_refuse_the_exact_program_this_lane_runs() {
    // Backend equivalence: exactly one engine claims `yield` today, and the
    // two that cannot lower it refuse the very same source with their own
    // stable codes rather than silently differing from the interpreter.
    let program = resolved(ASK);
    assert!(matches!(
        run_resumable_effect(&program, "app.ask", &[ArgumentValue::Int(41)], MAX_STEPS)
            .unwrap()
            .step,
        ResumableStep::Suspended { .. }
    ));
    let native = crate::codegen::emit_hir_c(&program).unwrap_err();
    assert_eq!(native.code, "SPX-B116");
    let wasm = crate::wasm::emit_resolved_module(&program).unwrap_err();
    assert_eq!(wasm.code, "SPX-W126");
}

#[test]
fn a_float_request_replays_by_bits_so_drift_detection_is_exact() {
    let source = r#"
module test.resumable_effects_float;
@id("app.ask")
fn ask(seed: f64) -> f64
    yields f64 -> f64
{
    let answer = yield seed;
    answer
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let program = hir::resolve(
        &crate::parse(source, Path::new("resumable-effects-float.spx")).expect("it parses"),
    )
    .expect("it resolves");
    let negative_zero = ArgumentValue::Float64(-0.0);
    let (state, binding, request) = suspension(&program, &[negative_zero.clone()]);
    assert_eq!(request, negative_zero);
    // `-0.0 == 0.0` in IEEE, but they are distinct requests: presenting the
    // positive zero as the recorded request is drift, not a match.
    let refused = resume_resumable_effect(
        &program,
        "app.ask",
        &[negative_zero.clone()],
        &state,
        &binding,
        &ArgumentValue::Float64(0.0),
        &ArgumentValue::Float64(1.0),
        MAX_STEPS,
    )
    .unwrap_err();
    assert_eq!(refused[0].code, "SPX-F114");
    // The genuine recorded request replays.
    assert!(matches!(
        resume_resumable_effect(
            &program,
            "app.ask",
            &[negative_zero.clone()],
            &state,
            &binding,
            &negative_zero,
            &ArgumentValue::Float64(1.5),
            MAX_STEPS,
        )
        .unwrap()
        .step,
        ResumableStep::Completed {
            result: ArgumentValue::Float64(1.5),
            ..
        }
    ));
}

#[test]
fn equal_requests_from_different_arguments_cannot_alias_one_suspension() {
    let source = r#"
module test.resumable_effects_argument_binding;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
{
    let answer = yield 0;
    answer + seed
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let program = resolved(source);
    let (state, binding, request) = suspension(&program, &[ArgumentValue::Int(1)]);
    assert_eq!(request, ArgumentValue::Int(0));
    assert_eq!(
        suspension(&program, &[ArgumentValue::Int(2)]).2,
        ArgumentValue::Int(0),
        "negative control: both invocations genuinely request the same value"
    );
    let refused = resume_resumable_effect(
        &program,
        "app.ask",
        &[ArgumentValue::Int(2)],
        &state,
        &binding,
        &request,
        &ArgumentValue::Int(10),
        MAX_STEPS,
    )
    .unwrap_err();
    assert_eq!(refused[0].code, "SPX-F115");
}
