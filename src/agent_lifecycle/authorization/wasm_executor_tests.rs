use super::*;

const SOURCE: &str = r#"module test.wasm_target_binding;

@id("test.wasm_target_binding.identity")
fn identity(value: i64) -> i64 { value }

@id("test.wasm_target_binding.divide")
fn divide(left: i64, right: i64) -> i64 { left / right }

@id("test.wasm_target_binding.other")
fn other(value: i64) -> i64 { value + 1 }

@id("app.main")
fn main() -> i64 { 0 }
"#;

fn program() -> hir::ResolvedProgram {
    let checked =
        crate::check(SOURCE, Path::new("wasm-target-binding-test.spx")).expect("fixture checks");
    let program = hir::resolve(&checked).expect("fixture resolves");
    hir::validate(&program).expect("fixture validates");
    program
}

fn prepared(program: &hir::ResolvedProgram) -> PreparedRetainedCall {
    crate::interpreter::retained_call::prepare_retained_call(
        program,
        "test.wasm_target_binding.identity",
    )
    .expect("identity prepares")
}

#[test]
fn target_binding_rejects_source_and_subject_remints_before_any_build_or_node() {
    let program = program();
    let prepared = prepared(&program);
    let entry = program
        .functions
        .iter()
        .find(|function| function.id.as_str() == prepared.function_id())
        .expect("prepared entry belongs to fixture");
    let arguments = [RetainedValue::I64(7)];
    let binding = WasmTargetBinding::bind(SOURCE, &program, entry, &prepared, &arguments, 100)
        .expect("exact checked source binds");
    let selected = vec![entry.id.as_str().to_owned()];
    let descriptor = project::derive_public_api_descriptor(&program, &selected, binding.subject())
        .expect("bound descriptor derives");
    let artifact = binding
        .bind_artifact(&descriptor, &selected)
        .expect("descriptor retains exact target facts");
    artifact
        .verify_invocations(&selected)
        .expect("the selected export is exactly the invocation");
    let mut wrong_digest = artifact.clone();
    wrong_digest.descriptor_digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();
    let error = wrong_digest
        .verify_descriptor(&descriptor)
        .expect_err("a descriptor-digest remint cannot reach the carrier verifier");
    assert_eq!(error.code, "SPX-G570");
    assert!(error
        .message
        .contains("wasm_executor.binding.descriptor_drift"));

    let drifted = SOURCE.replace("{ value }", "{ value + 2 }");
    let error = WasmTargetBinding::bind(&drifted, &program, entry, &prepared, &arguments, 100)
        .expect_err("a same-id source remint cannot bind the original program");
    assert_eq!(error.code, "SPX-G570");
    assert!(error.message.contains("wasm_executor.binding.lifecycle"));

    for subject in [
        project::PublicApiSubject {
            project_schema: project::PUBLIC_OWNED_DATA_PROJECT_SCHEMA,
            project_revision:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            workspace_revision: &binding.lifecycle_identity,
            project_graph_digest: &binding.invocation_identity,
        },
        project::PublicApiSubject {
            project_schema: project::PUBLIC_OWNED_DATA_PROJECT_SCHEMA,
            project_revision: &binding.source_revision,
            workspace_revision:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            project_graph_digest: &binding.invocation_identity,
        },
        project::PublicApiSubject {
            project_schema: project::PUBLIC_OWNED_DATA_PROJECT_SCHEMA,
            project_revision: &binding.source_revision,
            workspace_revision: &binding.lifecycle_identity,
            project_graph_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        },
    ] {
        let reminted = project::derive_public_api_descriptor(&program, &selected, subject)
            .expect("a syntactically valid but differently bound descriptor derives");
        let error = binding
            .bind_artifact(&reminted, &selected)
            .expect_err("a reminted descriptor subject is never target-authenticated");
        assert_eq!(error.code, "SPX-G570");
        assert!(error.message.contains("wasm_executor.binding.descriptor"));
    }

    let changed_arguments = [RetainedValue::I64(8)];
    let changed =
        WasmTargetBinding::bind(SOURCE, &program, entry, &prepared, &changed_arguments, 100)
            .expect("a distinct legitimate invocation binds separately");
    assert_ne!(binding.invocation_identity, changed.invocation_identity);
    let error = artifact
        .verify_invocations(&["test.wasm_target_binding.other".to_owned()])
        .expect_err("a selected-export remint cannot invoke a different function");
    assert_eq!(error.code, "SPX-G570");
    assert!(error.message.contains("wasm_executor.binding.invocation"));
}

#[test]
fn structured_outcome_rejects_malformed_and_mismatched_status_before_publication() {
    let ok = "{\"schema\":\"semaprax.agent-wasm-stage-outcome.v1\",\"kind\":\"returned\",\"value\":\"7\"}";
    let malformed_tail = format!("{ok}\n{{\"schema\":false}}\n");
    assert!(decode_node_outcomes(&malformed_tail, 2).is_err());

    let mismatch = "{\"schema\":\"semaprax.agent-wasm-stage-outcome.v1\",\"kind\":\"language_failure\",\"raw_status\":4,\"status\":{\"schema\":\"semaprax.status.v1\",\"domain_id\":\"semaprax.arithmetic.v1\",\"code\":5,\"class\":\"arithmetic\",\"retryable\":false}}\n";
    let error = decode_node_outcomes(mismatch, 1)
        .expect_err("raw and normalized status disagreement must not publish an outcome");
    assert!(error
        .message
        .contains("wasm_executor.outcome.status_mismatch"));

    let failure = "{\"schema\":\"semaprax.agent-wasm-stage-outcome.v1\",\"kind\":\"language_failure\",\"raw_status\":9,\"status\":{\"schema\":\"semaprax.status.v1\",\"domain_id\":\"semaprax.contract.v1\",\"code\":1,\"class\":\"contract\",\"retryable\":false}}";
    assert!(decode_node_outcomes(&format!("{failure}\n{ok}\n"), 2).is_err());
}

#[test]
fn node_envelope_preserves_compiler_owned_failure_and_fresh_process_recovers() {
    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let program = program();
    let prepared = crate::interpreter::retained_call::prepare_retained_call(
        &program,
        "test.wasm_target_binding.divide",
    )
    .expect("divide function prepares");
    let failed = run(
        SOURCE,
        &program,
        &prepared,
        &[RetainedValue::I64(7), RetainedValue::I64(0)],
        100,
    )
    .expect("a checked language failure is an execution outcome");
    assert_eq!(
        failed.outcome,
        RetainedCallOutcome::LanguageFailure(crate::runtime_status::normalize_arithmetic(
            StatusCase::DivisionByZero
        ))
    );
    let healthy = run(
        SOURCE,
        &program,
        &prepared,
        &[RetainedValue::I64(14), RetainedValue::I64(2)],
        100,
    )
    .expect("a fresh local target remains usable after the settled failure");
    assert_eq!(
        healthy.outcome,
        RetainedCallOutcome::Returned(RetainedValue::I64(7))
    );
}

#[test]
fn injected_aggregate_stops_after_one_checked_failure_before_arena_reuse() {
    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    const AGGREGATE_SOURCE: &str = r#"module test.wasm_target_binding.aggregate;

@id("test.wasm_target_binding.aggregate.pair")
record Pair {
    @id("test.wasm_target_binding.aggregate.pair.left") left: i64,
    @id("test.wasm_target_binding.aggregate.pair.right") right: i64,
}

@id("test.wasm_target_binding.aggregate.divide")
fn divide(value: i64, divisor: i64) -> Pair {
    Pair { left: value / divisor, right: value }
}

@id("app.main")
fn main() -> i64 { 0 }
"#;
    let checked = crate::check(
        AGGREGATE_SOURCE,
        Path::new("wasm-target-binding-aggregate.spx"),
    )
    .unwrap();
    let program = hir::resolve(&checked).unwrap();
    hir::validate(&program).unwrap();
    let prepared = crate::interpreter::retained_call::prepare_retained_call(
        &program,
        "test.wasm_target_binding.aggregate.divide",
    )
    .expect("aggregate divide prepares");
    let failed = run(
        AGGREGATE_SOURCE,
        &program,
        &prepared,
        &[RetainedValue::I64(7), RetainedValue::I64(0)],
        100,
    )
    .expect("one checked failure settles the whole aggregate projection");
    assert_eq!(
        failed.outcome,
        RetainedCallOutcome::LanguageFailure(crate::runtime_status::normalize_arithmetic(
            StatusCase::DivisionByZero
        ))
    );
}
