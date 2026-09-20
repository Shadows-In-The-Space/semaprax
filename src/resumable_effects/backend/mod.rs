//! Compiler-private backend parity evidence for the minimal source-level
//! resumable slice.
//!
//! This is not a runtime scheduler and does not reuse [`super::core`]: start
//! and resume are separate, synchronous target executions of the yield-free
//! HIR projections produced by [`super::lowering`]. A suspension is bound to
//! the exact checked plan and invocation argument bits. Resume replays the
//! request projection and compares exact scalar bits before it executes the
//! continuation projection.
//!
//! The facade deliberately makes no step/fuel accounting or cleanup-event
//! claim. The admitted lowering is Copy-scalar and cleanup-free. Core Wasm
//! additionally refuses `usize` with the scalar-profile diagnostic because
//! that target's public scalar ABI intentionally has no host-width carrier.
//! Signed zero is transported and compared by bits. Arbitrary NaN payload
//! preservation is not claimed by the Core Wasm runner because its existing
//! scalar package crosses JavaScript `Number`; a future raw-bit adapter would
//! be required to make that stronger claim.

use crate::cleanup_plan::{ContractPhase, StatusCase};
use crate::conformance::{
    NormalizedStatus, ARITHMETIC_STATUS_DOMAIN_V1, CONTRACT_STATUS_DOMAIN_V1,
};
use crate::diagnostic::Diagnostic;
use crate::hir::{ResolvedProgram, ResolvedType};
use crate::resumable_effects::lowering::{
    ResumablePlan, ResumableScalar, ResumableStateId, ResumableSuspensionBinding,
};

mod native;
mod wasm;

#[cfg(test)]
mod tests;

const TYPE_MISMATCH: &str = "SPX-F113";
const SUSPENSION_DRIFT: &str = "SPX-F114";
const SUSPENSION_MISMATCH: &str = "SPX-F115";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    NativeO0,
    NativeO2,
    CoreWasm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendSuspension {
    state: ResumableStateId,
    request: ResumableScalar,
    binding: ResumableSuspensionBinding,
}

impl BackendSuspension {
    pub fn state(&self) -> &ResumableStateId {
        &self.state
    }

    pub fn request(&self) -> &ResumableScalar {
        &self.request
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendStep {
    Suspended(BackendSuspension),
    Complete {
        state: ResumableStateId,
        result: ResumableScalar,
    },
    LanguageFailure(NormalizedStatus),
}

enum TargetOutcome {
    Success(ResumableScalar),
    LanguageFailure(NormalizedStatus),
}

/// Execute the request projection on one real backend.
pub fn run(
    backend: Backend,
    program: &ResolvedProgram,
    plan: &ResumablePlan,
    arguments: &[ResumableScalar],
) -> Result<BackendStep, Diagnostic> {
    validate_arguments(&plan.start.function, arguments)?;
    let projected = plan.start_program(program)?;
    let request = match execute(
        backend,
        &projected,
        plan.function_id.as_str(),
        arguments,
        &plan.suspension.request_type,
    )? {
        TargetOutcome::Success(request) => request,
        TargetOutcome::LanguageFailure(status) => return Ok(BackendStep::LanguageFailure(status)),
    };
    Ok(BackendStep::Suspended(BackendSuspension {
        state: plan.suspension.state.id.clone(),
        request,
        binding: plan.suspension_binding(arguments),
    }))
}

/// Replay the request projection and, only after its exact bits agree with the
/// recorded suspension, execute the continuation projection.
pub fn resume(
    backend: Backend,
    program: &ResolvedProgram,
    plan: &ResumablePlan,
    arguments: &[ResumableScalar],
    suspension: &BackendSuspension,
    answer: ResumableScalar,
) -> Result<BackendStep, Diagnostic> {
    validate_arguments(&plan.start.function, arguments)?;
    if !scalar_matches_type(&answer, &plan.suspension.response_type) {
        return Err(type_mismatch(format!(
            "resume value has type {}, but this suspension requires {}",
            scalar_type_text(&answer),
            resolved_type_text(&plan.suspension.response_type),
        )));
    }
    if suspension.state != plan.suspension.state.id
        || suspension.binding != plan.suspension_binding(arguments)
    {
        return Err(suspension_mismatch(
            "resumable suspension does not belong to this exact plan and invocation argument bits",
        ));
    }

    let start = plan.start_program(program)?;
    let replayed = match execute(
        backend,
        &start,
        plan.function_id.as_str(),
        arguments,
        &plan.suspension.request_type,
    )? {
        TargetOutcome::Success(request) => request,
        TargetOutcome::LanguageFailure(status) => return Ok(BackendStep::LanguageFailure(status)),
    };
    if replayed != suspension.request {
        return Err(drift(format!(
            "resumable request changed during replay: recorded {}, replayed {}",
            scalar_debug(&suspension.request),
            scalar_debug(&replayed),
        )));
    }

    let resume = plan.resume_program(program)?;
    let mut resumed_arguments = arguments.to_vec();
    resumed_arguments.push(answer);
    validate_arguments(&plan.resume.function, &resumed_arguments)?;
    let result = match execute(
        backend,
        &resume,
        plan.function_id.as_str(),
        &resumed_arguments,
        &plan.resume.function.return_type,
    )? {
        TargetOutcome::Success(result) => result,
        TargetOutcome::LanguageFailure(status) => return Ok(BackendStep::LanguageFailure(status)),
    };
    Ok(BackendStep::Complete {
        state: plan.complete.id.clone(),
        result,
    })
}

fn execute(
    backend: Backend,
    program: &ResolvedProgram,
    function_id: &str,
    arguments: &[ResumableScalar],
    result_type: &ResolvedType,
) -> Result<TargetOutcome, Diagnostic> {
    match backend {
        Backend::NativeO0 => native::execute(program, function_id, arguments, result_type, "-O0"),
        Backend::NativeO2 => native::execute(program, function_id, arguments, result_type, "-O2"),
        Backend::CoreWasm => wasm::execute(program, function_id, arguments, result_type),
    }
}

fn validate_arguments(
    function: &crate::hir::ResolvedFunction,
    arguments: &[ResumableScalar],
) -> Result<(), Diagnostic> {
    if function.params.len() != arguments.len() {
        return Err(type_mismatch(format!(
            "resumable invocation expected {} arguments but received {}",
            function.params.len(),
            arguments.len(),
        )));
    }
    for (index, (parameter, argument)) in function.params.iter().zip(arguments).enumerate() {
        if !scalar_matches_type(argument, &parameter.ty) {
            return Err(type_mismatch(format!(
                "resumable argument {index} has type {}, but parameter `{}` requires {}",
                scalar_type_text(argument),
                parameter.name,
                resolved_type_text(&parameter.ty),
            )));
        }
    }
    Ok(())
}

fn scalar_matches_type(value: &ResumableScalar, ty: &ResolvedType) -> bool {
    matches!(
        (value, ty),
        (ResumableScalar::I64(_), ResolvedType::I64)
            | (ResumableScalar::I32(_), ResolvedType::I32)
            | (ResumableScalar::U8(_), ResolvedType::U8)
            | (ResumableScalar::Usize(_), ResolvedType::Usize)
            | (ResumableScalar::Char(_), ResolvedType::Char)
            | (ResumableScalar::F32(_), ResolvedType::F32)
            | (ResumableScalar::F64(_), ResolvedType::F64)
            | (ResumableScalar::Bool(_), ResolvedType::Bool)
    )
}

fn scalar_type_text(value: &ResumableScalar) -> &'static str {
    match value {
        ResumableScalar::I64(_) => "i64",
        ResumableScalar::I32(_) => "i32",
        ResumableScalar::U8(_) => "u8",
        ResumableScalar::Usize(_) => "usize",
        ResumableScalar::Char(_) => "char",
        ResumableScalar::F32(_) => "f32",
        ResumableScalar::F64(_) => "f64",
        ResumableScalar::Bool(_) => "bool",
    }
}

fn resolved_type_text(ty: &ResolvedType) -> &'static str {
    match ty {
        ResolvedType::I64 => "i64",
        ResolvedType::I32 => "i32",
        ResolvedType::U8 => "u8",
        ResolvedType::Usize => "usize",
        ResolvedType::Char => "char",
        ResolvedType::F32 => "f32",
        ResolvedType::F64 => "f64",
        ResolvedType::Bool => "bool",
        _ => "non-scalar",
    }
}

fn scalar_debug(value: &ResumableScalar) -> String {
    match value {
        ResumableScalar::I64(value) => format!("i64:{:016x}", *value as u64),
        ResumableScalar::I32(value) => format!("i32:{:08x}", *value as u32),
        ResumableScalar::U8(value) => format!("u8:{value:02x}"),
        ResumableScalar::Usize(value) => format!("usize:{value:016x}"),
        ResumableScalar::Char(value) => format!("char:{value:08x}"),
        ResumableScalar::F32(bits) => format!("f32:{bits:08x}"),
        ResumableScalar::F64(bits) => format!("f64:{bits:016x}"),
        ResumableScalar::Bool(value) => format!("bool:{}", u8::from(*value)),
    }
}

fn type_mismatch(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io(TYPE_MISMATCH, message)
}

fn drift(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io(SUSPENSION_DRIFT, message)
}

fn suspension_mismatch(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io(SUSPENSION_MISMATCH, message)
}

fn backend_failure(code: &'static str, detail: impl Into<String>) -> Diagnostic {
    Diagnostic::io(code, detail)
}

fn normalized_status(domain: &str, code: u32) -> Result<NormalizedStatus, Diagnostic> {
    let status = match (domain, code) {
        (ARITHMETIC_STATUS_DOMAIN_V1, 1) => NormalizedStatus::arithmetic(StatusCase::AddOverflow),
        (ARITHMETIC_STATUS_DOMAIN_V1, 2) => NormalizedStatus::arithmetic(StatusCase::SubOverflow),
        (ARITHMETIC_STATUS_DOMAIN_V1, 3) => NormalizedStatus::arithmetic(StatusCase::MulOverflow),
        (ARITHMETIC_STATUS_DOMAIN_V1, 4) => {
            NormalizedStatus::arithmetic(StatusCase::DivisionByZero)
        }
        (ARITHMETIC_STATUS_DOMAIN_V1, 5) => {
            NormalizedStatus::arithmetic(StatusCase::DivisionOverflow)
        }
        (ARITHMETIC_STATUS_DOMAIN_V1, 6) => {
            NormalizedStatus::arithmetic(StatusCase::RemainderByZero)
        }
        (ARITHMETIC_STATUS_DOMAIN_V1, 7) => {
            NormalizedStatus::arithmetic(StatusCase::RemainderOverflow)
        }
        (ARITHMETIC_STATUS_DOMAIN_V1, 8) => {
            NormalizedStatus::arithmetic(StatusCase::NegationOverflow)
        }
        (CONTRACT_STATUS_DOMAIN_V1, 1) => NormalizedStatus::contract(ContractPhase::Requires),
        (CONTRACT_STATUS_DOMAIN_V1, 2) => NormalizedStatus::contract(ContractPhase::Ensures),
        _ => {
            return Err(backend_failure(
                "SPX-F105",
                format!("resumable target returned unknown normalized status {domain}:{code}"),
            ));
        }
    };
    Ok(status)
}
