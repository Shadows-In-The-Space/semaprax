//! Retained multi-argument call seam for Reference Interpreter v1.
//!
//! One admitted product is prepared once from an already-resolved program and
//! then invoked repeatedly with typed arguments: a non-entrypoint function
//! selected by stable id, monomorphic scalar and Copy-class arguments, and
//! owned record and variant arguments and results. Preparation is the only
//! place `hir::validate` and the closure scan run; every later invocation
//! re-checks retained identities and the admitted signature and nothing else.
//!
//! The frozen zero-argument entrypoint product keeps its exact admission and
//! its known answers: the last case reads the same entrypoint through both the
//! canonical envelope route and the new seam and requires them to agree.

use super::*;

use semaprax::hir::{self, DeclarationId};
use semaprax::interpreter::retained_call::{
    evaluate_retained_call, prepare_retained_call, RetainedCallOutcome, RetainedField,
    RetainedRecord, RetainedValue, RetainedVariant,
};
use semaprax::interpreter::OwnedDataCleanupEvent;

/// Every declaration is explicit-ID, monomorphic, and effect-free. The stage
/// shapes are exactly the closed subset the retained seam admits: direct
/// scalars, a Copy class carrier, an owned-byte record, and an owned-byte
/// variant.
const RETAINED_FIXTURE: &str = r#"
module test.interpreter_retained_call;

@id("stage.gauge")
class Gauge {
    @id("stage.gauge.reading") reading: i64,
    @id("stage.gauge.armed") armed: bool,

    @id("stage.gauge.score")
    fn score(self: Gauge) -> i64 { self.reading + self.reading }
}

@id("stage.packet")
record Packet {
    @id("stage.packet.payload") payload: Bytes,
    @id("stage.packet.marker") marker: i64,
}

@id("stage.outcome")
variant Outcome {
    @id("stage.outcome.accepted") Accepted {
        @id("stage.outcome.accepted.payload") payload: Bytes,
    },
    @id("stage.outcome.rejected") Rejected {
        @id("stage.outcome.rejected.code") code: i64,
    },
}

/// Owned String Variant v1 (`85014337`): a direct `string` case field,
/// sibling to a Copy scalar case.
@id("stage.signal")
variant Signal {
    @id("stage.signal.message") Message {
        @id("stage.signal.message.text") text: string,
    },
    @id("stage.signal.code") Code {
        @id("stage.signal.code.value") value: i64,
    },
}

/// Copy Aggregate Variant Payload v1 (`77879d76`): a case field naming a
/// further drop-free, Copy-closed nested record. `Proposal` stays a plain
/// Copy tagged union end to end, so it is a bare (non-`own`) parameter.
@id("stage.inner")
record Inner {
    @id("stage.inner.x") x: i64,
    @id("stage.inner.flag") flag: bool,
}

@id("stage.proposal")
variant Proposal {
    @id("stage.proposal.wrapped") Wrapped {
        @id("stage.proposal.wrapped.value") value: Inner,
    },
    @id("stage.proposal.plain") Plain {
        @id("stage.proposal.plain.value") value: i64,
    },
}

@id("stage.authorize")
fn authorize(reading: i64, limit: i64, armed: bool) -> bool {
    armed && reading <= limit
}

@id("stage.measure")
fn measure(gauge: Gauge, limit: i64) -> i64 {
    if limit <= 0 { 0 } else { gauge.score() }
}

@id("stage.weigh")
fn weigh(packet: own Packet) -> i64 {
    match own packet {
        Packet { payload: payload, marker: marker } =>
            if byte_len(bytes_as_slice(payload)) == 4usize { marker } else { 0 - marker },
    }
}

@id("stage.relay")
fn relay(packet: own Packet) -> Packet { packet }

@id("stage.classify")
fn classify(outcome: own Outcome) -> Outcome { outcome }

@id("stage.relay_signal")
fn relay_signal(signal: own Signal) -> Signal { signal }

@id("stage.reduce")
fn reduce(proposal: Proposal) -> Proposal { proposal }

@id("stage.label")
fn label(value: string) -> string { value }

@id("stage.checked")
fn checked(value: i64) -> i64 requires value > 0 { value + 1 }

@id("app.main")
fn main() -> i64 { 42 }
"#;

/// Signatures the interpreter itself executes but that carry values outside
/// the retained seam's exact-transport vocabulary. Direct `string` used to be
/// here (`closed.label`) but is now admitted: see `stage.label` and the
/// direct-string-argument test below.
const CLOSED_TRANSPORT_FIXTURE: &str = r#"
module test.interpreter_retained_closed_transport;

@id("closed.ratio") fn ratio(value: f64) -> f64 { value }
@id("closed.letter") fn letter(value: char) -> char { value }
@id("closed.result") fn width(value: i64) -> f32 { 0.5f32 }

@id("app.main")
fn main() -> i64 { 7 }
"#;

fn resolved(source: &str, name: &str) -> hir::ResolvedProgram {
    let parsed = parse(source, Path::new(name)).expect("retained fixture parses");
    let diagnostics = verify::verify(&parsed);
    assert!(
        diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.severity.is_error()),
        "{name}: {diagnostics:?}"
    );
    hir::resolve(&parsed).expect("retained fixture resolves")
}

fn fixture() -> hir::ResolvedProgram {
    resolved(RETAINED_FIXTURE, "interpreter-retained-call.spx")
}

fn field(id: &str, value: RetainedValue) -> RetainedField {
    RetainedField {
        field: DeclarationId::new(id),
        value,
    }
}

fn packet(payload: &[u8], marker: i64) -> RetainedValue {
    RetainedValue::Record(RetainedRecord {
        record: DeclarationId::new("stage.packet"),
        fields: vec![
            field(
                "stage.packet.payload",
                RetainedValue::Bytes(payload.to_vec()),
            ),
            field("stage.packet.marker", RetainedValue::I64(marker)),
        ],
    })
}

fn returned(evaluation: RetainedCallOutcome) -> RetainedValue {
    match evaluation {
        RetainedCallOutcome::Returned(value) => value,
        other => panic!("expected a returned value, observed {other:?}"),
    }
}

#[test]
fn retained_call_dispatches_a_non_entrypoint_function_by_stable_id() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.authorize")
        .expect("a non-entrypoint multi-argument function is admitted");
    assert_eq!(prepared.function_id(), "stage.authorize");
    assert_eq!(prepared.parameter_count(), 3);
    assert!(prepared.function_ids().any(|id| id == "stage.authorize"));
    assert!(prepared.origin_nodes() > 0);
    assert!(prepared.index_bytes() > 0);
    // The seam selects the named function, never the module entrypoint.
    assert_ne!(prepared.function_id(), program.entrypoint.as_str());

    let evaluation = evaluate_retained_call(
        &program,
        &prepared,
        &[
            RetainedValue::I64(3),
            RetainedValue::I64(5),
            RetainedValue::Bool(true),
        ],
        10_000,
    )
    .expect("the admitted product evaluates");
    assert_eq!(evaluation.function_id.as_str(), "stage.authorize");
    assert_eq!(returned(evaluation.outcome), RetainedValue::Bool(true));
    assert!(evaluation.cleanup_events.is_empty());
    assert!(evaluation.steps_used > 0);
    assert_eq!(evaluation.max_steps, 10_000);
}

#[test]
fn one_retained_product_serves_several_invocations_without_reverification() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.authorize").expect("admitted");
    let cases = [
        (3i64, 5i64, true, true),
        (9, 5, true, false),
        (3, 5, false, false),
        (5, 5, true, true),
    ];
    for (reading, limit, armed, expected) in cases {
        let evaluation = evaluate_retained_call(
            &program,
            &prepared,
            &[
                RetainedValue::I64(reading),
                RetainedValue::I64(limit),
                RetainedValue::Bool(armed),
            ],
            10_000,
        )
        .expect("the retained product evaluates again");
        assert_eq!(
            returned(evaluation.outcome),
            RetainedValue::Bool(expected),
            "authorize({reading}, {limit}, {armed})"
        );
    }

    // Retention is observable, not merely documented: append a duplicate
    // function so the program no longer passes `hir::validate`. Preparation,
    // which validates, now fails; the already retained product, which does
    // not, keeps dispatching to the same retained vector positions.
    let mut drifted = fixture();
    let duplicate = drifted.functions[0].clone();
    drifted.functions.push(duplicate);
    assert!(
        prepare_retained_call(&drifted, "stage.authorize").is_err(),
        "preparation must re-verify and reject the duplicated program"
    );
    let evaluation = evaluate_retained_call(
        &drifted,
        &prepared,
        &[
            RetainedValue::I64(3),
            RetainedValue::I64(5),
            RetainedValue::Bool(true),
        ],
        10_000,
    )
    .expect("the retained product does not re-verify its program");
    assert_eq!(returned(evaluation.outcome), RetainedValue::Bool(true));
}

#[test]
fn retained_call_accepts_a_copy_class_argument() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.measure").expect("admitted");
    let gauge = RetainedValue::Record(RetainedRecord {
        record: DeclarationId::new("stage.gauge"),
        fields: vec![
            field("stage.gauge.reading", RetainedValue::I64(21)),
            field("stage.gauge.armed", RetainedValue::Bool(true)),
        ],
    });
    let evaluation =
        evaluate_retained_call(&program, &prepared, &[gauge, RetainedValue::I64(1)], 10_000)
            .expect("the Copy class carrier is staged");
    assert_eq!(returned(evaluation.outcome), RetainedValue::I64(42));
    // A Copy carrier owns no cleanup leaf, so it settles nothing.
    assert!(evaluation.cleanup_events.is_empty());
}

#[test]
fn retained_call_stages_an_owned_record_argument() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.weigh").expect("admitted");
    let evaluation =
        evaluate_retained_call(&program, &prepared, &[packet(&[1, 2, 3, 4], 7)], 10_000)
            .expect("the owned record carrier is staged");
    assert_eq!(returned(evaluation.outcome), RetainedValue::I64(7));

    // The same retained product observes a different staged payload.
    let evaluation = evaluate_retained_call(&program, &prepared, &[packet(&[1, 2], 7)], 10_000)
        .expect("the owned record carrier is staged again");
    assert_eq!(returned(evaluation.outcome), RetainedValue::I64(-7));

    // A zero-length owned payload is still a distinct logical allocation.
    let evaluation = evaluate_retained_call(&program, &prepared, &[packet(&[], 5)], 10_000)
        .expect("an empty owned payload is staged");
    assert_eq!(returned(evaluation.outcome), RetainedValue::I64(-5));
}

#[test]
fn retained_call_round_trips_an_owned_record_argument_and_result() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.relay").expect("admitted");
    let evaluation = evaluate_retained_call(&program, &prepared, &[packet(&[9, 8], 11)], 10_000)
        .expect("the owned record round-trips");
    assert_eq!(returned(evaluation.outcome), packet(&[9, 8], 11));
    // Exactly one owned leaf is copied out and settled at the boundary.
    assert_eq!(
        evaluation.cleanup_events,
        [OwnedDataCleanupEvent::CopyOutAndSettleBytes]
    );
}

#[test]
fn retained_call_round_trips_owned_variant_arguments_and_results() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.classify").expect("admitted");

    let accepted = RetainedValue::Variant(RetainedVariant {
        variant: DeclarationId::new("stage.outcome"),
        case: DeclarationId::new("stage.outcome.accepted"),
        fields: vec![field(
            "stage.outcome.accepted.payload",
            RetainedValue::Bytes(vec![5, 6, 7]),
        )],
    });
    let evaluation =
        evaluate_retained_call(&program, &prepared, std::slice::from_ref(&accepted), 10_000)
            .expect("the owned variant round-trips");
    assert_eq!(returned(evaluation.outcome), accepted);
    assert_eq!(
        evaluation.cleanup_events,
        [OwnedDataCleanupEvent::CopyOutAndSettleBytes]
    );

    let rejected = RetainedValue::Variant(RetainedVariant {
        variant: DeclarationId::new("stage.outcome"),
        case: DeclarationId::new("stage.outcome.rejected"),
        fields: vec![field("stage.outcome.rejected.code", RetainedValue::I64(-3))],
    });
    let evaluation =
        evaluate_retained_call(&program, &prepared, std::slice::from_ref(&rejected), 10_000)
            .expect("the Copy case round-trips");
    assert_eq!(returned(evaluation.outcome), rejected);
    // A case with no owned payload settles nothing.
    assert!(evaluation.cleanup_events.is_empty());
}

/// Issue #216: a direct owned `string` argument and result. `string`'s raw
/// UTF-8 bytes travel through the `RetainedValue::Bytes` carrier -- the
/// declared parameter type, not the carrier shape, says it is text.
#[test]
fn retained_call_stages_and_returns_a_direct_string_argument() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.label").expect("admitted");
    let evaluation = evaluate_retained_call(
        &program,
        &prepared,
        &[RetainedValue::Bytes(b"agent proposal".to_vec())],
        10_000,
    )
    .expect("the direct string argument is staged");
    assert_eq!(
        returned(evaluation.outcome),
        RetainedValue::Bytes(b"agent proposal".to_vec())
    );
    // A local interpreter String is a uniquely owned Rust allocation, not an
    // `Arc`-shared carrier, so it settles through no boundary cleanup event.
    assert!(evaluation.cleanup_events.is_empty());
}

/// Issue #216: Owned String Variant v1 (`85014337`) round-trips through the
/// retained-call seam -- both the owned `string` case and its Copy sibling.
#[test]
fn retained_call_round_trips_an_owned_string_variant_arguments_and_results() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.relay_signal").expect("admitted");

    let message = RetainedValue::Variant(RetainedVariant {
        variant: DeclarationId::new("stage.signal"),
        case: DeclarationId::new("stage.signal.message"),
        fields: vec![field(
            "stage.signal.message.text",
            RetainedValue::Bytes(b"authorize".to_vec()),
        )],
    });
    let evaluation =
        evaluate_retained_call(&program, &prepared, std::slice::from_ref(&message), 10_000)
            .expect("the owned string variant round-trips");
    assert_eq!(returned(evaluation.outcome), message);
    // No `OwnedDataCleanupEvent` exists for a String leaf: it settles by
    // ordinary Rust ownership, not a boundary finalizer call.
    assert!(evaluation.cleanup_events.is_empty());

    let code = RetainedValue::Variant(RetainedVariant {
        variant: DeclarationId::new("stage.signal"),
        case: DeclarationId::new("stage.signal.code"),
        fields: vec![field("stage.signal.code.value", RetainedValue::I64(9))],
    });
    let evaluation =
        evaluate_retained_call(&program, &prepared, std::slice::from_ref(&code), 10_000)
            .expect("the Copy case round-trips");
    assert_eq!(returned(evaluation.outcome), code);
    assert!(evaluation.cleanup_events.is_empty());
}

/// Issue #216: Copy Aggregate Variant Payload v1 (`77879d76`) round-trips
/// through the retained-call seam. `Proposal` stays a plain Copy tagged union
/// end to end -- a bare (non-`own`) parameter and result, no cleanup events,
/// and a nested record case field (`Wrapped { value: Inner }`) rather than a
/// flat scalar.
#[test]
fn retained_call_round_trips_a_copy_aggregate_nested_record_variant() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.reduce").expect("admitted");

    let wrapped = RetainedValue::Variant(RetainedVariant {
        variant: DeclarationId::new("stage.proposal"),
        case: DeclarationId::new("stage.proposal.wrapped"),
        fields: vec![field(
            "stage.proposal.wrapped.value",
            RetainedValue::Record(RetainedRecord {
                record: DeclarationId::new("stage.inner"),
                fields: vec![
                    field("stage.inner.x", RetainedValue::I64(7)),
                    field("stage.inner.flag", RetainedValue::Bool(true)),
                ],
            }),
        )],
    });
    let evaluation =
        evaluate_retained_call(&program, &prepared, std::slice::from_ref(&wrapped), 10_000)
            .expect("the Copy aggregate nested-record variant round-trips");
    assert_eq!(returned(evaluation.outcome), wrapped);
    // A plain Copy tagged union owns no cleanup leaf anywhere in its closure.
    assert!(evaluation.cleanup_events.is_empty());

    let plain = RetainedValue::Variant(RetainedVariant {
        variant: DeclarationId::new("stage.proposal"),
        case: DeclarationId::new("stage.proposal.plain"),
        fields: vec![field("stage.proposal.plain.value", RetainedValue::I64(11))],
    });
    let evaluation =
        evaluate_retained_call(&program, &prepared, std::slice::from_ref(&plain), 10_000)
            .expect("the flat scalar case round-trips");
    assert_eq!(returned(evaluation.outcome), plain);
    assert!(evaluation.cleanup_events.is_empty());
}

/// Widening the vocabulary to admit `string` and Copy Aggregate Variant
/// Payload v1 case fields must not weaken the identity-keyed safety checks:
/// a foreign variant identity and an unauthenticated case still fail closed
/// with `SPX-F103`, exactly as they do for the pre-existing owned-byte
/// variant profile.
#[test]
fn retained_call_still_rejects_foreign_identities_for_the_widened_variant_shapes() {
    let program = fixture();

    let prepared = prepare_retained_call(&program, "stage.relay_signal").expect("admitted");
    let foreign_variant = RetainedValue::Variant(RetainedVariant {
        variant: DeclarationId::new("stage.outcome"),
        case: DeclarationId::new("stage.signal.message"),
        fields: vec![field(
            "stage.signal.message.text",
            RetainedValue::Bytes(b"x".to_vec()),
        )],
    });
    let errors = evaluate_retained_call(&program, &prepared, &[foreign_variant], 10_000)
        .expect_err("a foreign variant identity fails closed");
    assert!(
        errors.iter().any(|item| item.code == "SPX-F103"),
        "{errors:?}"
    );

    let prepared = prepare_retained_call(&program, "stage.reduce").expect("admitted");
    let unknown_case = RetainedValue::Variant(RetainedVariant {
        variant: DeclarationId::new("stage.proposal"),
        case: DeclarationId::new("stage.outcome.rejected"),
        fields: vec![field("stage.proposal.plain.value", RetainedValue::I64(1))],
    });
    let errors = evaluate_retained_call(&program, &prepared, &[unknown_case], 10_000)
        .expect_err("an unauthenticated case identity fails closed");
    assert!(
        errors.iter().any(|item| item.code == "SPX-F103"),
        "{errors:?}"
    );
}

#[test]
fn retained_call_reports_contract_failure_and_fuel_exhaustion() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.checked").expect("admitted");

    let ok = evaluate_retained_call(&program, &prepared, &[RetainedValue::I64(4)], 10_000)
        .expect("the satisfied precondition evaluates");
    assert_eq!(returned(ok.outcome), RetainedValue::I64(5));
    assert!(ok.failure.is_none());

    let failed = evaluate_retained_call(&program, &prepared, &[RetainedValue::I64(0)], 10_000)
        .expect("the violated precondition is a language failure, not an error");
    assert!(
        matches!(failed.outcome, RetainedCallOutcome::LanguageFailure(_)),
        "{:?}",
        failed.outcome
    );
    let detail = failed
        .failure
        .expect("a contract failure records its frame");
    assert_eq!(detail.function_id, "stage.checked");
    assert_eq!(detail.phase_text(), "requires");

    let exhausted = evaluate_retained_call(&program, &prepared, &[RetainedValue::I64(4)], 1)
        .expect("a capacity limit is fail-closed, not an error");
    assert_eq!(exhausted.outcome, RetainedCallOutcome::FuelExhausted);
}

#[test]
fn retained_call_rejects_an_unresolved_stable_id() {
    let program = fixture();
    let errors = prepare_retained_call(&program, "stage.absent")
        .expect_err("an unresolved identity has no admitted product");
    assert!(
        errors
            .iter()
            .any(|item| item.code == "SPX-F102" && item.message.contains("unsupported_callee")),
        "{errors:?}"
    );
    // Admission, never an evaluator guard.
    assert!(
        errors.iter().all(|item| item.code != "SPX-F105"),
        "{errors:?}"
    );
}

#[test]
fn retained_call_rejects_argument_and_result_types_outside_its_vocabulary() {
    let program = resolved(
        CLOSED_TRANSPORT_FIXTURE,
        "interpreter-retained-closed-transport.spx",
    );
    for (id, reason) in [
        ("closed.ratio", "unsupported_parameter_type"),
        ("closed.letter", "unsupported_parameter_type"),
        ("closed.result", "unsupported_result_type"),
    ] {
        let errors = match prepare_retained_call(&program, id) {
            Ok(_) => panic!("`{id}` must stay outside the retained call vocabulary"),
            Err(errors) => errors,
        };
        assert!(
            errors
                .iter()
                .any(|item| item.code == "SPX-F102" && item.message.contains(reason)),
            "{id}: {errors:?}"
        );
        // A closed admission reason, never a panic and never an SPX-F105
        // evaluator guard.
        assert!(
            errors.iter().all(|item| item.code != "SPX-F105"),
            "{id}: {errors:?}"
        );
        // The rejection is located on the offending declaration.
        assert!(
            errors
                .iter()
                .any(|item| item.span.is_some_and(|span| span.start < span.end)),
            "{id}: {errors:?}"
        );
    }
}

#[test]
fn retained_call_rejects_an_incompatible_signature() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.authorize").expect("admitted");

    let errors = evaluate_retained_call(
        &program,
        &prepared,
        &[RetainedValue::I64(1), RetainedValue::I64(2)],
        10_000,
    )
    .expect_err("an argument count mismatch fails closed");
    assert!(
        errors.iter().any(|item| item.code == "SPX-F103"),
        "{errors:?}"
    );

    let errors = evaluate_retained_call(
        &program,
        &prepared,
        &[
            RetainedValue::I64(1),
            RetainedValue::I64(2),
            RetainedValue::I64(3),
        ],
        10_000,
    )
    .expect_err("an argument type mismatch fails closed");
    assert!(
        errors.iter().any(|item| item.code == "SPX-F103"),
        "{errors:?}"
    );

    // Aggregate arguments are keyed by identity: a foreign record identity and
    // an unknown field both fail closed rather than being coerced.
    let prepared = prepare_retained_call(&program, "stage.weigh").expect("admitted");
    let foreign = RetainedValue::Record(RetainedRecord {
        record: DeclarationId::new("stage.gauge"),
        fields: vec![
            field("stage.packet.payload", RetainedValue::Bytes(vec![1])),
            field("stage.packet.marker", RetainedValue::I64(1)),
        ],
    });
    let errors = evaluate_retained_call(&program, &prepared, &[foreign], 10_000)
        .expect_err("a foreign record identity fails closed");
    assert!(
        errors.iter().any(|item| item.code == "SPX-F103"),
        "{errors:?}"
    );

    let renamed = RetainedValue::Record(RetainedRecord {
        record: DeclarationId::new("stage.packet"),
        fields: vec![
            field("stage.packet.payload", RetainedValue::Bytes(vec![1])),
            field("stage.gauge.reading", RetainedValue::I64(1)),
        ],
    });
    let errors = evaluate_retained_call(&program, &prepared, &[renamed], 10_000)
        .expect_err("an unknown field identity fails closed");
    assert!(
        errors.iter().any(|item| item.code == "SPX-F103"),
        "{errors:?}"
    );
}

#[test]
fn a_retained_product_does_not_dispatch_into_a_different_program() {
    let program = fixture();
    let prepared = prepare_retained_call(&program, "stage.authorize").expect("admitted");
    let other = resolved(
        CLOSED_TRANSPORT_FIXTURE,
        "interpreter-retained-closed-transport.spx",
    );
    let errors = evaluate_retained_call(
        &other,
        &prepared,
        &[
            RetainedValue::I64(3),
            RetainedValue::I64(5),
            RetainedValue::Bool(true),
        ],
        10_000,
    )
    .expect_err("a retained index never dispatches into another program");
    assert!(
        errors.iter().any(|item| item.code == "SPX-F105"),
        "{errors:?}"
    );
}

#[test]
fn the_zero_argument_entrypoint_path_keeps_its_known_answer() {
    let program = fixture();
    let path = write_temp(RETAINED_FIXTURE);
    let envelope = interpret_case(&path, "app.main", &[]).expect("the entrypoint is admitted");
    cleanup(&path);
    let payload: serde_json::Value = serde_json::from_str(&envelope).expect("envelope JSON");
    let outcome = &payload["payload"]["outcome"];
    assert_eq!(outcome["kind"], "returned", "{envelope}");
    assert_eq!(outcome["type"], "i64", "{envelope}");
    assert_eq!(outcome["value"], "42", "{envelope}");

    // The additive seam observes the same entrypoint answer through the
    // retained product; it does not replace or reinterpret the frozen route.
    let prepared = prepare_retained_call(&program, "app.main").expect("admitted");
    assert_eq!(prepared.parameter_count(), 0);
    let evaluation =
        evaluate_retained_call(&program, &prepared, &[], 10_000).expect("the entrypoint evaluates");
    assert_eq!(returned(evaluation.outcome), RetainedValue::I64(42));
}
