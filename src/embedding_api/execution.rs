//! Explicitly authorized, bounded execution for the compiler embedding API.
//!
//! This child owns the only effectful operation exposed by
//! `crate::embedding_api`: deterministic evaluation of the checked entrypoint
//! through the existing prepared resolved-HIR kernel. It owns no provider,
//! filesystem path, project snapshot, process, network, or generated-target
//! authority.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::diagnostic::{Diagnostic, Severity};
use crate::interpreter::{
    self, PreparedCancellation, PreparedResolvedEvaluationOutcome, MAX_STEPS_LIMIT,
};

use super::PANIC_NORMALIZED_DIAGNOSTIC_CODE;

/// Explicit host authority to evaluate an admitted source entrypoint.
///
/// There is no `Default`: a host must opt into execution deliberately, and
/// source text cannot manufacture this token. The token grants only the
/// deterministic prepared-HIR evaluator used below; it grants no host effect
/// provider or ambient authority.
#[derive(Clone, Debug)]
pub struct ExecutionCapability {
    reason: String,
}

impl ExecutionCapability {
    #[must_use]
    pub fn grant(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Monotonic, cooperative cancellation for one embedded execution request.
#[derive(Default)]
pub struct ExecutionCancellation {
    cancelled: AtomicBool,
}

impl ExecutionCancellation {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Per-call deterministic execution limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionOptions {
    max_steps: usize,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self {
            max_steps: interpreter::DEFAULT_MAX_STEPS,
        }
    }
}

impl ExecutionOptions {
    /// Construct a bounded evaluation limit using the interpreter's canonical
    /// `1..=MAX_STEPS_LIMIT` validation and diagnostics.
    pub fn new(max_steps: usize) -> Result<Self, Diagnostic> {
        if !(1..=MAX_STEPS_LIMIT).contains(&max_steps) {
            return Err(Diagnostic::io(
                "SPX-F101",
                format!("embedded execution max_steps must be between 1 and {MAX_STEPS_LIMIT}"),
            ));
        }
        Ok(Self { max_steps })
    }

    #[must_use]
    pub const fn max_steps(&self) -> usize {
        self.max_steps
    }
}

/// Closed execution result from the admitted zero-argument `i64` entrypoint
/// profile. Language-level failure remains a settled result, while malformed
/// source/admission/guard faults appear in [`ExecutionReport::diagnostics`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionOutcome {
    ReturnedI64(i64),
    LanguageFailure { status_json: String },
    FuelExhausted,
    CallDepthExceeded,
    Cancelled { before_step: usize },
}

/// Closed report from [`execute_entry_source`]. It exposes no AST, resolved
/// HIR, prepared closure, provider, or runtime handle.
#[derive(Clone, Debug)]
pub struct ExecutionReport {
    pub unit_name: String,
    pub ok: bool,
    pub diagnostics: Vec<Diagnostic>,
    pub outcome: Option<ExecutionOutcome>,
    pub steps_used: usize,
    pub max_steps: usize,
}

fn failure_report(
    unit_name: &str,
    diagnostics: Vec<Diagnostic>,
    max_steps: usize,
) -> ExecutionReport {
    ExecutionReport {
        unit_name: unit_name.to_owned(),
        ok: false,
        diagnostics,
        outcome: None,
        steps_used: 0,
        max_steps,
    }
}

fn cancelled_report(unit_name: &str, max_steps: usize, before_step: usize) -> ExecutionReport {
    ExecutionReport {
        unit_name: unit_name.to_owned(),
        ok: true,
        diagnostics: Vec::new(),
        outcome: Some(ExecutionOutcome::Cancelled { before_step }),
        steps_used: before_step,
        max_steps,
    }
}

/// Execute the caller-supplied source's declared entrypoint through the
/// deterministic zero-argument `i64` interpreter profile.
///
/// The capability, exact source bytes, fuel limit, and cancellation signal are
/// explicit. No path is opened and no source-native effect is given a host
/// provider: the existing prepared kernel rechecks its admitted closure before
/// it starts evaluation. A compiler panic is normalized into
/// `SPX-EMB001`, never unwound into the embedding host.
pub fn execute_entry_source(
    _capability: &ExecutionCapability,
    unit_name: &str,
    source: &str,
    options: &ExecutionOptions,
    cancellation: &ExecutionCancellation,
) -> ExecutionReport {
    let max_steps = options.max_steps;
    if cancellation.is_cancelled() {
        return cancelled_report(unit_name, max_steps, 0);
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let program = crate::parse(source, unit_name).map_err(|item| vec![item])?;
        let resolved = crate::hir::resolve(&program)?;
        let prepared =
            interpreter::prepare_resolved_zero_arg_i64(&resolved, resolved.entrypoint.as_str())?;
        std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("semaprax-embedded-execution".to_owned())
                .stack_size(interpreter::EVALUATION_STACK_BYTES)
                .spawn_scoped(scope, || {
                    interpreter::evaluate_prepared_resolved_zero_arg_i64(
                        &resolved,
                        &prepared,
                        max_steps,
                        0,
                        PreparedCancellation::Atomic(&cancellation.cancelled),
                    )
                })
                .map_err(|error| {
                    vec![Diagnostic::io(
                        "SPX-F105",
                        format!("embedded evaluation thread failed to start: {error}"),
                    )]
                })?;
            worker.join().map_err(|_| {
                vec![Diagnostic {
                    code: PANIC_NORMALIZED_DIAGNOSTIC_CODE,
                    severity: Severity::Error,
                    message: "the embedding execution worker panicked after HIR validation and \
                              was normalized before it could cross the embedding API boundary"
                        .to_owned(),
                    path: Some(unit_name.to_owned()),
                    span: None,
                    help: Some(
                        "this names an embedding-boundary defect, not a property of the checked \
                         source; report it against the compiler"
                            .to_owned(),
                    ),
                }]
            })?
        })
    }));
    match outcome {
        Ok(Ok(evaluated)) => {
            let outcome = match evaluated.outcome {
                PreparedResolvedEvaluationOutcome::ReturnedI64(value) => {
                    ExecutionOutcome::ReturnedI64(value)
                }
                PreparedResolvedEvaluationOutcome::LanguageFailure(status) => {
                    ExecutionOutcome::LanguageFailure {
                        status_json: status.to_json(),
                    }
                }
                PreparedResolvedEvaluationOutcome::FuelExhausted => ExecutionOutcome::FuelExhausted,
                PreparedResolvedEvaluationOutcome::CallDepthExceeded => {
                    ExecutionOutcome::CallDepthExceeded
                }
                PreparedResolvedEvaluationOutcome::Cancelled { before_step } => {
                    ExecutionOutcome::Cancelled { before_step }
                }
                PreparedResolvedEvaluationOutcome::GuardError(detail) => {
                    return failure_report(
                        unit_name,
                        vec![Diagnostic::io("SPX-F105", detail)],
                        max_steps,
                    );
                }
            };
            ExecutionReport {
                unit_name: unit_name.to_owned(),
                ok: true,
                diagnostics: Vec::new(),
                outcome: Some(outcome),
                steps_used: evaluated.steps_used,
                max_steps: evaluated.max_steps,
            }
        }
        Ok(Err(diagnostics)) => failure_report(unit_name, diagnostics, max_steps),
        Err(_panic_payload) => failure_report(
            unit_name,
            vec![Diagnostic {
                code: PANIC_NORMALIZED_DIAGNOSTIC_CODE,
                severity: Severity::Error,
                message: format!(
                    "the embedding execution boundary caught a panic while evaluating {unit_name:?} \
                     and normalized it to this diagnostic instead of letting the unwind cross \
                     the embedding API boundary"
                ),
                path: Some(unit_name.to_owned()),
                span: None,
                help: Some(
                    "this names an embedding-boundary defect, not a property of the checked \
                     source; report it against the compiler"
                        .to_owned(),
                ),
            }],
            max_steps,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: &str = "module app.entry;\n\n@id(\"app.main\")\nfn main() -> i64\n{\n    42\n}\n";

    #[test]
    fn explicit_capability_executes_the_admitted_pathless_entry() {
        let cancellation = ExecutionCancellation::new();
        let report = execute_entry_source(
            &ExecutionCapability::grant("embedded test"),
            "/definitely/not/a/source/path.spx",
            ENTRY,
            &ExecutionOptions::new(100).expect("valid limit"),
            &cancellation,
        );
        assert!(report.ok, "expected ok, got {:?}", report.diagnostics);
        assert!(report.diagnostics.is_empty());
        assert_eq!(report.outcome, Some(ExecutionOutcome::ReturnedI64(42)));
        assert!(report.steps_used > 0);
    }

    #[test]
    fn cancellation_before_parsing_settles_without_reading_or_executing_source() {
        let cancellation = ExecutionCancellation::new();
        cancellation.cancel();
        let report = execute_entry_source(
            &ExecutionCapability::grant("embedded test"),
            "not-opened.spx",
            "not even source",
            &ExecutionOptions::default(),
            &cancellation,
        );
        assert!(report.ok);
        assert_eq!(report.steps_used, 0);
        assert_eq!(
            report.outcome,
            Some(ExecutionOutcome::Cancelled { before_step: 0 })
        );
    }

    #[test]
    fn invalid_source_is_a_closed_diagnostic_not_an_execution_attempt() {
        let report = execute_entry_source(
            &ExecutionCapability::grant("embedded test"),
            "invalid.spx",
            "module app.invalid;\n",
            &ExecutionOptions::default(),
            &ExecutionCancellation::new(),
        );
        assert!(!report.ok);
        assert_eq!(report.outcome, None);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].code, "SPX-P101");
    }

    #[test]
    fn fuel_exhaustion_is_a_closed_settled_outcome() {
        let report = execute_entry_source(
            &ExecutionCapability::grant("embedded test"),
            "entry.spx",
            ENTRY,
            &ExecutionOptions::new(1).expect("valid limit"),
            &ExecutionCancellation::new(),
        );
        assert!(
            report.ok,
            "expected settled fuel result, got {:?}",
            report.diagnostics
        );
        assert_eq!(report.outcome, Some(ExecutionOutcome::FuelExhausted));
    }
}
