//! Resumable Effects v1 (issue #204): interpreter suspend/resume execution
//! of one `yields`-declaring function.
//!
//! `24c1d166` admitted the `yield` slice across parser, canonical formatter,
//! resolver/HIR, verifier, semantic graph, and both backends, but no engine
//! executed it: native refused with `SPX-B116`, Wasm with `SPX-W126`, and the
//! interpreter refused at its own admission gate. This module is the first
//! public compiler engine that runs it. Ordinary native and Wasm emission
//! still refuses with those stable codes; compiler-private parity runners use
//! `resumable_effects::lowering`'s independently validated yield-free
//! projections instead of weakening either ordinary emitter's admission.
//!
//! # The execution model
//!
//! `hir::resolve_yield` already states it: a suspension is resumed by
//! *re-executing the function from its entry* with the resume value
//! substituted at the yield site. That is sound here, and only here, because
//! the admitted slice forecloses every way a re-execution could differ from
//! or duplicate the original prefix:
//!
//! - a `yields`-declaring function may declare no `uses` effects
//!   (`SPX-T302`), so the replayed prefix contacts no host and can
//!   redispatch nothing;
//! - every parameter and intermediate value is an admitted Copy scalar
//!   (`SPX-T301`/`SPX-T303`), so nothing owned is live across the
//!   suspension and the replay allocates and frees nothing;
//! - `parser::yields` admits exactly one `yield`, only at the function's own
//!   top level (`SPX-T297`/`SPX-T298`), so control cannot branch around or
//!   repeat the yield site.
//! - `resumable_effects::lowering` rejects a call closure that reaches any
//!   other `yields`-declaring function. The one-site proof is therefore over
//!   the complete reachable computation, not merely the selected function's
//!   source body.
//!
//! Replay is therefore a *re-use* of an already-computed prefix, not a
//! second, possibly divergent execution -- and this module proves that
//! rather than assuming it. On every resume the replayed prefix recomputes
//! the request and it must equal the request the suspension recorded;
//! disagreement is refused as drift (`SPX-F114`) instead of being papered
//! over. This is the same discipline `resumable_effects::core`'s
//! `RequestDrift` enforces at the Rust reference level, now applied to real
//! `.spx` source.
//!
//! Request equality is not a continuation identity: two argument vectors can
//! compute the same request and different suffix results. Each suspension
//! therefore carries a domain-separated binding over the exact checked HIR,
//! the lowering plan and yield-site identities, and the bit-exact original
//! scalar arguments. Resume refuses a mismatched state or binding with
//! `SPX-F115`. The binding commits to the replay inputs; it grants no effect
//! authority.
//!
//! # Typed resume
//!
//! A resume value is checked against the function's *declared* response type
//! (`yields Request -> Response`) before the program is ever entered, and a
//! mismatch is refused with `SPX-F113`. The recorded request is checked the
//! same way against the declared request type. A resumed computation is
//! therefore checked, not trusted: no interpreter lane can hand a `bool`
//! answer to a suspension that declared `yields i64 -> i64`.
//!
//! # No authority
//!
//! This lane opens no file, spawns no process, and contacts no network: a
//! suspension is proof data about what the program asked for, never
//! permission to satisfy it. Who answers a request, and whether they were
//! entitled to, is the caller's -- `resumable_effects::capability`'s --
//! concern, outside this module entirely.

use crate::conformance::NormalizedStatus;
use crate::diagnostic::Diagnostic;
use crate::hir::{self, ResolvedFunction, ResolvedType};
use crate::resumable_effects::lowering::{
    self, ResumablePlan, ResumableScalar, ResumableStateId, ResumableSuspensionBinding,
};

use super::prepared::PreparedCancellation;
use super::{
    admitted_resolved_functions, argument_error, option_error, resolved_signature_is_admitted,
    scan_closure, selection_error, ArgumentValue, Evaluator, Flow, FunctionLookup, Value,
    EVALUATION_STACK_BYTES, MAX_STEPS_LIMIT, REASON_AUTOMATIC_IDENTITY, REASON_UNSUPPORTED_CALLEE,
};

/// The function named for this lane declares no `yields` clause.
const REASON_NOT_RESUMABLE: &str = "not_a_resumable_effect_function";
/// The function is outside the interpreter's admitted scalar profile.
const REASON_OUTSIDE_PROFILE: &str = "outside_resumable_effect_profile";

/// A resume value's type disagrees with the declared `yields` signature.
const RESUME_TYPE_MISMATCH: &str = "SPX-F113";
/// The replayed prefix recomputed a different request than the suspension
/// recorded. Fails closed: no resumed value is produced.
const REQUEST_DRIFT: &str = "SPX-F114";
/// The caller presented a continuation state or invocation binding that was
/// not produced by this exact checked program and exact argument vector.
const SUSPENSION_MISMATCH: &str = "SPX-F115";

/// The `Flow::Guard` detail a fresh suspension travels on. It never escapes
/// this module: [`evaluate_resumable`] converts it into
/// [`ResumableStep::Suspended`] using the request parked in [`Resumption`].
pub(super) const SUSPENDED_AT_YIELD: &str = "resumable-effect invocation suspended at its `yield`";
/// The `Flow::Guard` detail every *ordinary* interpreter lane keeps for a
/// `yield`. Those lanes refuse a `yields`-declaring function at admission
/// long before its body is evaluated, so this is an unreachable-in-practice
/// refusal that stays explicit rather than becoming a silent fallthrough.
const YIELD_REFUSED: &str = "`yield` is not yet evaluated by the interpreter";
/// Structurally impossible: `parser::yields` admits exactly one `yield` per
/// function, so no single invocation can reach a second one.
const SECOND_YIELD: &str = "a resumable-effect invocation reached a second `yield`";

/// How one `Evaluator` treats the single `yield` its function may contain.
pub(super) enum Resumption {
    /// Every ordinary interpreter lane. `yield` is refused outright.
    Refused,
    /// A fresh resumable invocation: the first `yield` parks its request
    /// here and suspends.
    Fresh(Option<Value>),
    /// A replayed resumable invocation: the `yield` recomputes its request,
    /// must agree with `expected`, and then evaluates to `answer`.
    Replay {
        expected: Value,
        answer: Value,
        observed: bool,
    },
}

/// The one `yield` site's whole runtime behaviour, in one place.
pub(super) fn settle_yield(state: &mut Resumption, request: Value) -> Result<Value, Flow> {
    match state {
        Resumption::Refused => Err(Flow::Guard(YIELD_REFUSED)),
        Resumption::Fresh(parked) => {
            if parked.is_some() {
                return Err(Flow::Guard(SECOND_YIELD));
            }
            *parked = Some(request);
            Err(Flow::Guard(SUSPENDED_AT_YIELD))
        }
        Resumption::Replay {
            expected,
            answer,
            observed,
        } => {
            if *observed {
                return Err(Flow::Guard(SECOND_YIELD));
            }
            if !scalar_values_equal(&request, expected) {
                return Err(Flow::Guard(REQUEST_DRIFT));
            }
            *observed = true;
            clone_scalar(answer).ok_or(Flow::Guard("resume answer is not an admitted scalar"))
        }
    }
}

/// One settled outcome of starting or resuming a resumable-effect function.
#[derive(Clone, Debug, PartialEq)]
pub enum ResumableStep {
    /// The function reached its `yield` and produced this request. Nothing
    /// was dispatched: the caller owns deciding whether and how to answer.
    Suspended {
        state: ResumableStateId,
        binding: ResumableSuspensionBinding,
        request: ArgumentValue,
    },
    /// The function ran to its result -- on a resume, past the yield site.
    Completed {
        state: ResumableStateId,
        result: ArgumentValue,
    },
    LanguageFailure(NormalizedStatus),
    FuelExhausted,
    CallDepthExceeded,
    /// An impossible state after the caller's HIR validation.
    GuardError(String),
}

/// Deterministic facts from one resumable-effect start or resume.
#[derive(Clone, Debug, PartialEq)]
pub struct ResumableEvaluation {
    pub step: ResumableStep,
    pub steps_used: usize,
    pub max_steps: usize,
}

/// Run `function_id` until its single suspension, or to completion.
pub fn run_resumable_effect(
    program: &hir::ResolvedProgram,
    function_id: &str,
    arguments: &[ArgumentValue],
    max_steps: usize,
) -> Result<ResumableEvaluation, Vec<Diagnostic>> {
    evaluate_resumable(program, function_id, arguments, None, max_steps)
}

/// Resume a suspension of `function_id` by replaying its prefix under the
/// exact `arguments` that produced it and substituting `answer` at the yield
/// site.
///
/// `request` is the request the suspension recorded. It is not trusted: the
/// replayed prefix recomputes its own request and the two must agree
/// (`SPX-F114`). `answer` must have the declared response type
/// (`SPX-F113`). `state` and `binding` must identify this exact checked
/// program, yield site, and bit-exact original argument vector (`SPX-F115`).
pub fn resume_resumable_effect(
    program: &hir::ResolvedProgram,
    function_id: &str,
    arguments: &[ArgumentValue],
    state: &ResumableStateId,
    binding: &ResumableSuspensionBinding,
    request: &ArgumentValue,
    answer: &ArgumentValue,
    max_steps: usize,
) -> Result<ResumableEvaluation, Vec<Diagnostic>> {
    evaluate_resumable(
        program,
        function_id,
        arguments,
        Some((
            state.clone(),
            binding.clone(),
            request.clone(),
            answer.clone(),
        )),
        max_steps,
    )
}

fn evaluate_resumable(
    program: &hir::ResolvedProgram,
    function_id: &str,
    arguments: &[ArgumentValue],
    resume: Option<(
        ResumableStateId,
        ResumableSuspensionBinding,
        ArgumentValue,
        ArgumentValue,
    )>,
    max_steps: usize,
) -> Result<ResumableEvaluation, Vec<Diagnostic>> {
    if !(1..=MAX_STEPS_LIMIT).contains(&max_steps) {
        return Err(vec![option_error(format!(
            "resumable-effect evaluation max_steps must be between 1 and {MAX_STEPS_LIMIT}"
        ))]);
    }
    let entry = program
        .functions
        .iter()
        .find(|function| function.id.as_str() == function_id)
        .ok_or_else(|| {
            vec![selection_error(
                REASON_UNSUPPORTED_CALLEE,
                format!("resumable entry `{function_id}` is absent from the function index"),
            )]
        })?;
    if !program
        .declarations
        .declaration(&entry.id)
        .is_some_and(|declaration| declaration.identity_origin == hir::IdentityOrigin::Explicit)
    {
        return Err(vec![selection_error(
            REASON_AUTOMATIC_IDENTITY,
            format!("resumable entry `{function_id}` does not have an explicit stable identity"),
        )]);
    }
    let yields = entry.yields.as_ref().ok_or_else(|| {
        vec![selection_error(
            REASON_NOT_RESUMABLE,
            format!("`{function_id}` declares no `yields` clause; this lane runs only functions that can suspend"),
        )]
    })?;
    if !resolved_signature_is_admitted(entry, &program.declarations) {
        return Err(vec![selection_error(
            REASON_OUTSIDE_PROFILE,
            format!("resumable entry `{function_id}` is outside the interpreter profile"),
        )]);
    }
    let bound = bind_scalar_arguments(entry, arguments)?;
    let admitted = admitted_resolved_functions(program);
    scan_closure(function_id, &admitted, program)?;
    hir::validate(program).map_err(|error| vec![error])?;
    let plan = lowering::lower(program, entry).map_err(|error| vec![error])?;
    let scalar_arguments = resumable_scalars(arguments).ok_or_else(|| {
        vec![argument_error(
            "resumable invocation contains a non-scalar argument".to_owned(),
        )]
    })?;
    let expected_binding = plan.suspension_binding(&scalar_arguments);
    let resumption = match resume {
        None => Resumption::Fresh(None),
        Some((state, binding, request, answer)) => {
            if state != plan.suspension.state.id || binding != expected_binding {
                return Err(vec![Diagnostic::io(
                    SUSPENSION_MISMATCH,
                    format!(
                        "resuming `{function_id}` presented a suspension state or invocation binding that does not match this exact checked program, yield site, and argument vector"
                    ),
                )]);
            }
            Resumption::Replay {
                expected: typed_resume_value(&yields.request_type, &request, "request")?,
                answer: typed_resume_value(&yields.response_type, &answer, "answer")?,
                observed: false,
            }
        }
    };
    let closure_functions =
        super::closures::checked_functions(program).map_err(|error| vec![error])?;

    let evaluated = std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("semaprax-resumable-evaluate".to_owned())
            .stack_size(EVALUATION_STACK_BYTES)
            .spawn_scoped(scope, || {
                let mut evaluator = Evaluator::new_prepared(
                    FunctionLookup::Borrowed(&admitted),
                    closure_functions,
                    &program.declarations,
                    max_steps,
                    0,
                    PreparedCancellation::Never,
                );
                evaluator.resumption = resumption;
                let settled = evaluator.evaluate_entry(entry, &bound);
                let step =
                    settle_step(settled, &mut evaluator.resumption, &plan, &expected_binding);
                ResumableEvaluation {
                    step,
                    steps_used: evaluator.steps,
                    max_steps,
                }
            })
            .map_err(|error| {
                vec![option_error(format!(
                    "resumable-effect evaluation thread failed to start: {error}"
                ))]
            })?;
        worker.join().map_err(|_| {
            vec![option_error(
                "resumable-effect evaluation thread panicked".to_owned(),
            )]
        })
    })?;

    if evaluated.step == ResumableStep::GuardError(REQUEST_DRIFT.to_owned()) {
        return Err(vec![Diagnostic::io(
            REQUEST_DRIFT,
            format!(
                "resuming `{function_id}` replayed its prefix and recomputed a different request \
                 than the suspension recorded; the resume is refused rather than answered"
            ),
        )]);
    }
    Ok(evaluated)
}

/// Turn the evaluator's settled `Result` into one closed step, reading the
/// parked request for the suspension case.
fn settle_step(
    settled: Result<Value, Flow>,
    resumption: &mut Resumption,
    plan: &ResumablePlan,
    binding: &ResumableSuspensionBinding,
) -> ResumableStep {
    match settled {
        Ok(value) => match argument_of(&value) {
            Some(result) => ResumableStep::Completed {
                state: plan.complete.id.clone(),
                result,
            },
            None => ResumableStep::GuardError(
                "resumable-effect entry returned a non-scalar value".to_owned(),
            ),
        },
        Err(Flow::Guard(SUSPENDED_AT_YIELD)) => {
            let Resumption::Fresh(Some(request)) = resumption else {
                return ResumableStep::GuardError(
                    "a suspension escaped without parking its request".to_owned(),
                );
            };
            match argument_of(request) {
                Some(request) => ResumableStep::Suspended {
                    state: plan.suspension.state.id.clone(),
                    binding: binding.clone(),
                    request,
                },
                None => {
                    ResumableStep::GuardError("`yield` produced a non-scalar request".to_owned())
                }
            }
        }
        Err(Flow::Failure(status)) => ResumableStep::LanguageFailure(status),
        Err(Flow::Exhausted) => ResumableStep::FuelExhausted,
        Err(Flow::DepthExceeded) => ResumableStep::CallDepthExceeded,
        Err(Flow::Guard(detail)) => ResumableStep::GuardError(detail.to_owned()),
        Err(Flow::Residual(_)) => ResumableStep::GuardError(
            "owned postfix `?` residual escaped its function frame".to_owned(),
        ),
        Err(Flow::Cancelled { .. }) => {
            ResumableStep::GuardError("unexpected cancellation in resumable evaluation".to_owned())
        }
        Err(Flow::Utf8MaterializationLimitExceeded { .. }) => ResumableStep::GuardError(
            "unexpected UTF-8 materialization limit in resumable evaluation".to_owned(),
        ),
    }
}

fn resumable_scalars(arguments: &[ArgumentValue]) -> Option<Vec<ResumableScalar>> {
    arguments
        .iter()
        .map(|argument| {
            Some(match argument {
                ArgumentValue::Int(value) => ResumableScalar::I64(*value),
                ArgumentValue::Int32(value) => ResumableScalar::I32(*value),
                ArgumentValue::Uint8(value) => ResumableScalar::U8(*value),
                ArgumentValue::Usize(value) => ResumableScalar::Usize(*value),
                ArgumentValue::Char(value) => ResumableScalar::Char(*value),
                ArgumentValue::Float32(value) => ResumableScalar::F32(value.to_bits()),
                ArgumentValue::Float64(value) => ResumableScalar::F64(value.to_bits()),
                ArgumentValue::Bool(value) => ResumableScalar::Bool(*value),
                _ => return None,
            })
        })
        .collect()
}

/// Bind the caller's arguments positionally, refusing an arity or type
/// disagreement with the declared parameters before anything runs.
fn bind_scalar_arguments(
    entry: &ResolvedFunction,
    arguments: &[ArgumentValue],
) -> Result<Vec<(String, ArgumentValue)>, Vec<Diagnostic>> {
    if entry.params.len() != arguments.len() {
        return Err(vec![argument_error(format!(
            "`{}` takes {} argument(s); {} were supplied",
            entry.name,
            entry.params.len(),
            arguments.len()
        ))]);
    }
    let mut bound = Vec::with_capacity(arguments.len());
    for (index, (param, argument)) in entry.params.iter().zip(arguments.iter()).enumerate() {
        if scalar_of(&param.ty, argument).is_none() {
            return Err(vec![argument_error(format!(
                "argument {index} of `{}` is not an admitted scalar of the declared parameter type",
                entry.name
            ))]);
        }
        bound.push((param.id.as_str().to_owned(), argument.clone()));
    }
    Ok(bound)
}

/// Check one resume value against its declared type before the program runs.
fn typed_resume_value(
    declared: &ResolvedType,
    supplied: &ArgumentValue,
    role: &str,
) -> Result<Value, Vec<Diagnostic>> {
    scalar_of(declared, supplied).ok_or_else(|| {
        vec![Diagnostic::io(
            RESUME_TYPE_MISMATCH,
            format!(
                "resume {role} `{}` does not have the declared `yields` {role} type",
                supplied.type_text()
            ),
        )]
    })
}

/// The exact scalar `Value` an `ArgumentValue` denotes at `declared`, or
/// `None` when the two disagree. Deliberately total and exact: no widening,
/// no coercion, no signed/unsigned reinterpretation.
fn scalar_of(declared: &ResolvedType, supplied: &ArgumentValue) -> Option<Value> {
    Some(match (declared, supplied) {
        (ResolvedType::I64, ArgumentValue::Int(value)) => Value::Int(*value),
        (ResolvedType::I32, ArgumentValue::Int32(value)) => Value::Int32(*value),
        (ResolvedType::U8, ArgumentValue::Uint8(value)) => Value::Uint8(*value),
        (ResolvedType::Usize, ArgumentValue::Usize(value)) => Value::Usize(*value),
        (ResolvedType::Char, ArgumentValue::Char(value)) => Value::Char(*value),
        (ResolvedType::F32, ArgumentValue::Float32(value)) => Value::Float32(*value),
        (ResolvedType::F64, ArgumentValue::Float64(value)) => Value::Float64(*value),
        (ResolvedType::Bool, ArgumentValue::Bool(value)) => Value::Bool(*value),
        _ => return None,
    })
}

/// The `ArgumentValue` one scalar `Value` denotes. `None` for every
/// non-scalar carrier, which the admitted slice forecloses.
fn argument_of(value: &Value) -> Option<ArgumentValue> {
    Some(match value {
        Value::Int(inner) => ArgumentValue::Int(*inner),
        Value::Int32(inner) => ArgumentValue::Int32(*inner),
        Value::Uint8(inner) => ArgumentValue::Uint8(*inner),
        Value::Usize(inner) => ArgumentValue::Usize(*inner),
        Value::Char(inner) => ArgumentValue::Char(*inner),
        Value::Float32(inner) => ArgumentValue::Float32(*inner),
        Value::Float64(inner) => ArgumentValue::Float64(*inner),
        Value::Bool(inner) => ArgumentValue::Bool(*inner),
        _ => return None,
    })
}

fn clone_scalar(value: &Value) -> Option<Value> {
    argument_of(value).and_then(|argument| match argument {
        ArgumentValue::Int(inner) => Some(Value::Int(inner)),
        ArgumentValue::Int32(inner) => Some(Value::Int32(inner)),
        ArgumentValue::Uint8(inner) => Some(Value::Uint8(inner)),
        ArgumentValue::Usize(inner) => Some(Value::Usize(inner)),
        ArgumentValue::Char(inner) => Some(Value::Char(inner)),
        ArgumentValue::Float32(inner) => Some(Value::Float32(inner)),
        ArgumentValue::Float64(inner) => Some(Value::Float64(inner)),
        ArgumentValue::Bool(inner) => Some(Value::Bool(inner)),
        _ => None,
    })
}

/// Exact scalar identity for the drift check. Floats compare by bits, not by
/// IEEE equality, so a replayed `NaN` request agrees with the recorded one
/// and `-0.0` never silently passes for `0.0`.
fn scalar_values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Float32(left), Value::Float32(right)) => left.to_bits() == right.to_bits(),
        (Value::Float64(left), Value::Float64(right)) => left.to_bits() == right.to_bits(),
        (left, right) => argument_of(left).is_some() && left == right,
    }
}

#[cfg(test)]
mod tests;
