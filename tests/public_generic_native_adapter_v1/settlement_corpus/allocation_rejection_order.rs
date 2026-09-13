//! Issue #103 composition: result allocation rejection with ordered cleanup.
//! The in-process provider traces retain leaf indices; native is still checked
//! through the existing corpus probe for the shared status/resource oracle.

use semaprax::public_generic_abi::carrier::trace::{Direction, TraceEvent, TraceLabel};
use semaprax::public_generic_abi::interpreter::{InterpreterPgStatus, InterpreterProvider};
use semaprax::public_generic_abi::wasm::provider::WasmProvider;

use super::super::{compile_and_run_native, interpreter_binding, wasm_binding, Case};

const CASE_ID: &str = "result_allocation_rejection_releases_inputs_in_reverse_order";

fn case() -> Case {
    Case {
        case_id: CASE_ID,
        input_leaves: vec![b"first".to_vec(), b"second".to_vec()],
        failure_injection: Some(TraceLabel::ResultLeafAllocationCommitted),
        compound_cleanup_injection: None,
        expected_accepted: false,
        expected_status: InterpreterPgStatus::AllocationFailure as i32,
    }
}

fn assert_reverse_release_order(order: &[u32]) {
    assert_eq!(
        order,
        [1, 0],
        "input leaves must release in reverse allocation order"
    );
}

fn assert_trace_releases_in_reverse_order(trace: &[TraceEvent]) {
    let order: Vec<u32> = trace
        .iter()
        .filter(|event| {
            event.label == TraceLabel::LeafRelease && event.direction == Direction::Input
        })
        .filter_map(|event| event.leaf)
        .collect();
    assert_reverse_release_order(&order);
}

#[test]
fn result_allocation_rejection_preserves_ordered_input_release() {
    let case = case();
    let trusted = interpreter_binding();
    let mut interpreter = InterpreterProvider::open(
        super::super::DESCRIPTOR_FIXTURE,
        super::super::DESCRIPTOR_FIXTURE,
        &trusted.encode(),
        &trusted,
    )
    .unwrap();
    interpreter.test_inject_failure(TraceLabel::ResultLeafAllocationCommitted);
    let input = interpreter.input_prepare(&case.input_leaves).unwrap();
    assert_eq!(
        interpreter.call(input),
        Err(InterpreterPgStatus::AllocationFailure)
    );
    assert_trace_releases_in_reverse_order(interpreter.test_last_trace());
    assert_eq!(interpreter.live_allocations(), 0);
    assert_eq!(interpreter.live_handles(), 0);
    interpreter.close();

    let trusted = wasm_binding();
    let mut wasm = WasmProvider::open(
        super::super::DESCRIPTOR_FIXTURE,
        super::super::DESCRIPTOR_FIXTURE,
        &trusted.encode(),
        &trusted,
    )
    .unwrap();
    wasm.test_inject_failure(TraceLabel::ResultLeafAllocationCommitted);
    let input = wasm.input_prepare(&case.input_leaves).unwrap();
    assert_eq!(
        wasm.call(input),
        Err(semaprax::public_generic_abi::wasm::provider::WasmPgStatus::AllocationFailure)
    );
    assert_trace_releases_in_reverse_order(wasm.test_last_trace());
    assert_eq!(wasm.live_allocations(), 0);
    assert_eq!(wasm.live_handles(), 0);
    wasm.close();

    for optimization in ["-O0", "-O2"] {
        let native = compile_and_run_native(&[case.clone()], optimization);
        assert_eq!(native.len(), 1);
        assert!(!native[0].outcome.accepted);
        assert_eq!(native[0].outcome.primary_status, case.expected_status);
        assert_eq!(native[0].outcome.live_allocations, 0);
        assert_eq!(native[0].outcome.live_handles, 0);
    }
}

#[test]
#[should_panic(expected = "input leaves must release in reverse allocation order")]
fn ordered_release_oracle_rejects_a_forward_permutation() {
    assert_reverse_release_order(&[0, 1]);
}
