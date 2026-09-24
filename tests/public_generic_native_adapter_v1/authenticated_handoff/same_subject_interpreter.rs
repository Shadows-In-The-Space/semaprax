//! Actual retained evaluation, not the public-generic reference reversal model.
use semaprax::{
    conformance::{StatusClass, CONTRACT_REQUIRES_FALSE_CODE, CONTRACT_STATUS_DOMAIN_V1},
    hir::{DeclarationId, ResolvedProgram},
    interpreter::{
        retained_call::{
            evaluate_retained_call, prepare_retained_call, RetainedCallOutcome, RetainedField,
            RetainedRecord, RetainedValue,
        },
        OwnedDataCleanupEvent,
    },
    public_generic_abi::compiler_endpoint::AdmittedPublicGenericEndpointV1,
};

pub(super) fn observe(
    program: &ResolvedProgram,
    endpoint: &AdmittedPublicGenericEndpointV1,
    guard: bool,
) -> (u32, Vec<Vec<u8>>) {
    let prepared = prepare_retained_call(program, endpoint.export_id()).unwrap();
    let fields = &endpoint.descriptor().input_facts().fields;
    assert_eq!(fields.len(), super::PAYLOADS.len());
    let argument = RetainedValue::Record(RetainedRecord {
        record: DeclarationId::new("auth.pair"),
        fields: fields
            .iter()
            .zip(super::PAYLOADS)
            .map(|(field, bytes)| RetainedField {
                field: DeclarationId::new(&field.id),
                value: RetainedValue::Bytes(bytes.to_vec()),
            })
            .collect(),
    });
    // Wrong nominal identity is rejected by retained-call argument admission,
    // before an evaluator is constructed. It is not a language failure/result.
    let RetainedValue::Record(mut foreign) = argument.clone() else {
        unreachable!()
    };
    foreign.record = DeclarationId::new("not.auth.pair");
    let rejected = evaluate_retained_call(
        program,
        &prepared,
        &[RetainedValue::Record(foreign)],
        10_000,
    )
    .unwrap_err();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].code, "SPX-F103");
    assert!(rejected[0]
        .message
        .contains("record identity `not.auth.pair` disagrees with the declared `auth.pair`"));

    let observed =
        evaluate_retained_call(program, &prepared, std::slice::from_ref(&argument), 10_000)
            .unwrap();
    assert_eq!(observed.function_id.as_str(), endpoint.export_id());
    assert!(observed.steps_used > 0 && observed.steps_used <= observed.max_steps);
    if guard {
        assert_eq!(
            observed.outcome,
            RetainedCallOutcome::Returned(argument.clone())
        );
        assert!(observed.failure.is_none());
        assert_eq!(
            observed.cleanup_events,
            [OwnedDataCleanupEvent::CopyOutAndSettleBytes; 2]
        );
        let RetainedCallOutcome::Returned(RetainedValue::Record(result)) = observed.outcome else {
            unreachable!()
        };
        let payloads = result
            .fields
            .into_iter()
            .map(|field| {
                let RetainedValue::Bytes(bytes) = field.value else {
                    panic!("non-Bytes result leaf")
                };
                bytes
            })
            .collect();
        eprintln!(
            "interpreter success: two result copy-out settlement events; wrong-record SPX-F103"
        );
        (0, payloads)
    } else {
        let RetainedCallOutcome::LanguageFailure(status) = observed.outcome else {
            panic!(
                "requires false did not execute as a language failure: {:?}",
                observed.outcome
            )
        };
        assert_eq!(status.domain_id(), CONTRACT_STATUS_DOMAIN_V1);
        assert_eq!(status.code(), CONTRACT_REQUIRES_FALSE_CODE);
        assert_eq!(status.class(), StatusClass::Contract);
        let failure = observed.failure.unwrap();
        assert_eq!(failure.function_id, endpoint.export_id());
        assert_eq!(failure.phase_text(), "requires");
        assert_eq!(failure.clause_index, 0);
        // This API records result harvesting, not all input finalization. Zero
        // events means no result copy-out; it is not zero-cleanup/leak evidence.
        assert!(observed.cleanup_events.is_empty());
        eprintln!("interpreter requires failure: no result copy-out events; input-finalizer accounting unclaimed; wrong-record SPX-F103");
        (11, Vec::new())
    }
}
