//! Literal-edge regressions for the source-native Core Wasm stage executor.
//!
//! The injected driver reconstitutes stage arguments as checked `.spx`
//! literals. `i64::MIN` is special because its magnitude cannot be parsed as
//! a positive i64: only the canonical directly-negated spelling is admitted.
//! This gate executes that spelling through the interpreter, native C11 at
//! both optimization levels, and Core Wasm. The separate empty-`Bytes` case
//! remains a stable fail-closed diagnostic because the source language has no
//! admitted empty-array literal for the driver's `bytes_copy` construction.

use super::*;

fn dispatch(
    backend: authorization::StageBackend<'_>,
    compiled: &CompiledAgentLifecycle,
    task: &RetainedValue,
) -> Result<crate::interpreter::retained_call::RetainedCallEvaluation, Vec<Diagnostic>> {
    authorization::dispatch_on(
        backend,
        &compiled.program,
        compiled.binding.initialize.prepared(),
        std::slice::from_ref(task),
        DEFAULT_STAGE_STEPS,
    )
}

/// The synthesized driver spells `i64::MIN` as the language's canonical
/// signed-minimum literal, so all four existing execution legs receive and
/// return the same State carrier.
#[test]
fn stage_initialize_with_i64_minimum_agrees_on_interpreter_native_and_core_wasm() {
    if !native_wasm_tools_available() {
        eprintln!("skipping signed-minimum Wasm stage parity: clang or node unavailable");
        return;
    }

    let compiled = lifecycle();
    let task = payload(&compiled.binding.task, b"minimum".to_vec(), i64::MIN);
    let interpreter = dispatch(authorization::StageBackend::Interpreter, &compiled, &task)
        .expect("the interpreter initializes the signed-minimum task");
    let native_o0 = dispatch(authorization::StageBackend::Native, &compiled, &task)
        .expect("native -O0 initializes the signed-minimum task");
    let native_o2 = dispatch(
        authorization::StageBackend::NativeAtOptimization("-O2"),
        &compiled,
        &task,
    )
    .expect("native -O2 initializes the signed-minimum task");
    let wasm = dispatch(
        authorization::StageBackend::Wasm { source: MODULE },
        &compiled,
        &task,
    )
    .expect("Core Wasm initializes the signed-minimum task");

    assert_eq!(interpreter.outcome, native_o0.outcome, "native -O0");
    assert_eq!(interpreter.outcome, native_o2.outcome, "native -O2");
    assert_eq!(interpreter.outcome, wasm.outcome, "Core Wasm");
    let RetainedCallOutcome::Returned(state) = wasm.outcome else {
        panic!("initialize must return State, got {:?}", wasm.outcome);
    };
    let RetainedValue::Record(state) = state else {
        panic!("initialize must return a State record");
    };
    let budget = state
        .fields
        .iter()
        .find(|field| field.field.as_str().ends_with(".budget"))
        .expect("State has its persistent budget field");
    assert_eq!(budget.value, RetainedValue::I64(i64::MIN));
}

/// Empty byte arrays still have no source-native literal spelling for this
/// driver. Refusing before a build preserves the exact stable backend
/// diagnostic instead of silently substituting a different task.
#[test]
fn core_wasm_stage_executor_keeps_empty_bytes_as_a_stable_refusal() {
    let compiled = lifecycle();
    let task = payload(&compiled.binding.task, Vec::new(), 0);
    let errors = dispatch(
        authorization::StageBackend::Wasm { source: MODULE },
        &compiled,
        &task,
    )
    .expect_err("an empty Bytes task has no admitted synthesized-driver literal");

    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].code, "SPX-G570");
    assert!(
        errors[0]
            .message
            .contains("wasm_executor.argument.empty_bytes"),
        "the refusal names the exact unsupported literal shape: {}",
        errors[0].message
    );
}
