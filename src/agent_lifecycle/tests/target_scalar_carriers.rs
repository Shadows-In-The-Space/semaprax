//! Scalar-rich Result-carrier parity for target-native Agent stages (#182).
//!
//! `Task`, `State`, `Observation`, `Outcome`, and `Decision` remain in the
//! frozen lifecycle's existing `Bytes`/`i64` profile. `Result` is deliberately
//! wider: its `bool` and `usize` leaves prove that the target result codecs do
//! not silently drop source-admitted scalar data. `usize` is carried as the
//! language's target-independent `u64`, including `u64::MAX`; it is never
//! narrowed through a host `usize` or JavaScript `Number`.

use super::*;

const REPORT: &str = r#"@id("fixture.agent.type.result")
record Report {
    @id("fixture.agent.type.result.summary") summary: Bytes,
    @id("fixture.agent.type.result.budget") budget: i64,
    @id("fixture.agent.type.result.status") status: i64,
}
"#;

const SCALAR_REPORT: &str = r#"@id("fixture.agent.type.result")
record Report {
    @id("fixture.agent.type.result.summary") summary: Bytes,
    @id("fixture.agent.type.result.budget") budget: i64,
    @id("fixture.agent.type.result.status") status: i64,
    @id("fixture.agent.type.result.approved") approved: bool,
    @id("fixture.agent.type.result.count") count: usize,
}
"#;

const I32_REPORT: &str = r#"@id("fixture.agent.type.result")
record Report {
    @id("fixture.agent.type.result.summary") summary: Bytes,
    @id("fixture.agent.type.result.budget") budget: i64,
    @id("fixture.agent.type.result.status") status: i64,
    @id("fixture.agent.type.result.phase") phase: i32,
}
"#;

const REPORT_TAIL: &str = "        status: outcome.status + state.epoch,\n    }";

fn source(report: &str, tail: &str) -> String {
    MODULE
        .replacen(REPORT, report, 1)
        .replacen(REPORT_TAIL, tail, 1)
}

fn scalar_source() -> String {
    source(
        SCALAR_REPORT,
        "        status: outcome.status + state.epoch,\n        approved: urgent,\n        count: sequence,\n    }",
    )
}

fn unsupported_source() -> String {
    source(
        I32_REPORT,
        "        status: outcome.status + state.epoch,\n        phase: 7i32,\n    }",
    )
}

fn compile(source: &str) -> CompiledAgentLifecycle {
    compile_agent_lifecycle(
        source,
        "target-scalar-carriers.spx",
        &DEFINITION.replace("RUNTIME", RUNTIME_V1),
    )
    .expect("the checked scalar-result lifecycle binds")
}

fn returned(
    label: &str,
    evaluation: crate::interpreter::retained_call::RetainedCallEvaluation,
) -> RetainedValue {
    let RetainedCallOutcome::Returned(value) = evaluation.outcome else {
        panic!("{label} did not return a carrier");
    };
    value
}

fn dispatch(
    backend: authorization::StageBackend<'_>,
    compiled: &CompiledAgentLifecycle,
    prepared: &crate::interpreter::retained_call::PreparedRetainedCall,
    arguments: &[RetainedValue],
) -> RetainedCallEvaluation {
    authorization::dispatch_on(
        backend,
        &compiled.program,
        prepared,
        arguments,
        DEFAULT_STAGE_STEPS,
    )
    .unwrap_or_else(|errors| panic!("target-native scalar carrier dispatch: {errors:?}"))
}

/// Drives every deterministic stage through one backend. The report carries
/// both extra scalar leaves; the authorizing call also carries `u64::MAX` as
/// a genuine `usize` source argument so the generated drivers cannot route it
/// through a lossy host-number representation.
fn drive(
    backend: authorization::StageBackend<'_>,
    source: &str,
    compiled: &CompiledAgentLifecycle,
) -> Vec<RetainedValue> {
    let task = payload(&compiled.binding.task, b"scalar".to_vec(), 10);
    let initialized = returned(
        "initialize",
        dispatch(
            backend,
            compiled,
            compiled.binding.initialize.prepared(),
            std::slice::from_ref(&task),
        ),
    );

    // Reconstruct the backend selector for each dispatch: it is a small
    // `Copy` enum except for its borrowed source text, and every leg must run
    // the stage that produced its own preceding state carrier.
    let select = |kind| match kind {
        0 => authorization::StageBackend::Interpreter,
        1 => authorization::StageBackend::Native,
        2 => authorization::StageBackend::NativeAtOptimization("-O2"),
        _ => authorization::StageBackend::Wasm { source },
    };
    let kind = match backend {
        authorization::StageBackend::Interpreter => 0,
        authorization::StageBackend::Native => 1,
        authorization::StageBackend::NativeAtOptimization(_) => 2,
        authorization::StageBackend::Wasm { .. } => 3,
    };

    let observed = returned(
        "observe",
        dispatch(
            select(kind),
            compiled,
            compiled.binding.observe.prepared(),
            std::slice::from_ref(&initialized),
        ),
    );
    let arguments = [
        initialized.clone(),
        RetainedValue::I64(3),
        RetainedValue::Bool(true),
        RetainedValue::Usize(u64::MAX),
    ];
    let decision = returned(
        "authorize",
        dispatch(
            select(kind),
            compiled,
            compiled.binding.authorize.stage().prepared(),
            &arguments,
        ),
    );
    let outcome = payload(&compiled.binding.outcome, b"observed".to_vec(), 4);
    let mut reduce = arguments.to_vec();
    reduce.push(outcome);
    let report = returned(
        "reduce",
        dispatch(
            select(kind),
            compiled,
            compiled.binding.reduce.prepared(),
            &reduce,
        ),
    );
    vec![initialized, observed, decision, report]
}

#[test]
fn all_target_stage_legs_preserve_bool_and_u64_usize_result_leaves() {
    if !native_wasm_tools_available() {
        eprintln!("skipping scalar carrier parity: clang or node unavailable");
        return;
    }
    let source = scalar_source();
    let compiled = compile(&source);
    let expected = drive(authorization::StageBackend::Interpreter, &source, &compiled);
    for (label, backend) in [
        ("native -O0", authorization::StageBackend::Native),
        (
            "native -O2",
            authorization::StageBackend::NativeAtOptimization("-O2"),
        ),
        (
            "Core Wasm",
            authorization::StageBackend::Wasm { source: &source },
        ),
    ] {
        assert_eq!(
            drive(backend, &source, &compiled),
            expected,
            "{label} scalar-rich lifecycle transcript"
        );
    }

    let RetainedValue::Record(report) = expected.last().expect("terminal report") else {
        panic!("reduce returns the Result record");
    };
    assert!(report.fields.iter().any(|field| {
        field.field.as_str() == "fixture.agent.type.result.approved"
            && field.value == RetainedValue::Bool(true)
    }));
    assert!(report.fields.iter().any(|field| {
        field.field.as_str() == "fixture.agent.type.result.count"
            && field.value == RetainedValue::Usize(u64::MAX)
    }));
}

#[test]
fn unsupported_target_result_leaf_refuses_before_artifact_execution_and_leaves_healthy_profile_intact(
) {
    let unsupported = unsupported_source();
    let compiled = compile(&unsupported);
    let task = payload(&compiled.binding.task, b"refuse".to_vec(), 10);
    let state = returned(
        "interpreter initialize",
        dispatch(
            authorization::StageBackend::Interpreter,
            &compiled,
            compiled.binding.initialize.prepared(),
            std::slice::from_ref(&task),
        ),
    );
    let mut reduce = vec![
        state,
        RetainedValue::I64(3),
        RetainedValue::Bool(true),
        RetainedValue::Usize(u64::MAX),
    ];
    reduce.push(payload(&compiled.binding.outcome, b"observed".to_vec(), 4));
    for backend in [
        authorization::StageBackend::Native,
        authorization::StageBackend::NativeAtOptimization("-O2"),
        authorization::StageBackend::Wasm {
            source: &unsupported,
        },
    ] {
        let errors = authorization::dispatch_on(
            backend,
            &compiled.program,
            compiled.binding.reduce.prepared(),
            &reduce,
            DEFAULT_STAGE_STEPS,
        )
        .expect_err("an i32 result leaf is outside the target codec profile");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, "SPX-G570");
        assert!(errors[0].message.contains("result.leaf"));
    }

    let healthy_source = scalar_source();
    let healthy = compile(&healthy_source);
    let task = payload(&healthy.binding.task, b"healthy".to_vec(), 10);
    let evaluation = authorization::dispatch_on(
        authorization::StageBackend::Wasm {
            source: &healthy_source,
        },
        &healthy.program,
        healthy.binding.initialize.prepared(),
        std::slice::from_ref(&task),
        DEFAULT_STAGE_STEPS,
    )
    .expect("an earlier refusal cannot corrupt a later legitimate target dispatch");
    assert!(matches!(
        evaluation.outcome,
        RetainedCallOutcome::Returned(_)
    ));
}
