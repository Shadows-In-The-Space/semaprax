use super::*;
use crate::model_call_receipt::receipt::tests::sample_receipt;

fn canonical() -> String {
    valid_receipt().render()
}

fn valid_receipt() -> crate::model_call_receipt::ModelCallReceipt {
    let mut receipt = sample_receipt();
    receipt.proposal_grammar_digest = format!("sha256:{}", "a".repeat(64));
    receipt.request_digest = format!("sha256:{}", "b".repeat(64));
    receipt
}

#[test]
fn canonical_receipt_round_trips_to_the_existing_type() {
    let bytes = canonical();
    let decoded = decode_receipt(bytes.as_bytes()).unwrap();
    assert_eq!(decoded.render(), bytes);
    assert_eq!(decoded, valid_receipt());
}

#[test]
fn unknown_duplicate_and_reordered_fields_are_rejected() {
    let bytes = canonical();
    let unknown = bytes.replacen(
        "\"schema\":\"semaprax.model-call-receipt.v1\"",
        "\"extra\":1,\"schema\":\"semaprax.model-call-receipt.v1\"",
        1,
    );
    assert_eq!(
        decode_receipt(unknown.as_bytes()),
        Err(DecodeError::NonCanonical)
    );

    let duplicate = bytes.replacen(
        "\"schema\":\"semaprax.model-call-receipt.v1\"",
        "\"schema\":\"semaprax.model-call-receipt.v1\",\"schema\":\"semaprax.model-call-receipt.v1\"",
        1,
    );
    assert_eq!(
        decode_receipt(duplicate.as_bytes()),
        Err(DecodeError::NonCanonical)
    );

    let first = "{\"schema\":\"semaprax.model-call-receipt.v1\",\"agent_id\":\"sha256:agent\"";
    let reordered = bytes.replacen(
        first,
        "{\"agent_id\":\"sha256:agent\",\"schema\":\"semaprax.model-call-receipt.v1\"",
        1,
    );
    assert_eq!(
        decode_receipt(reordered.as_bytes()),
        Err(DecodeError::NonCanonical)
    );
}

#[test]
fn oversized_and_invalid_numbers_are_rejected() {
    let bytes = canonical();
    assert_eq!(
        decode_receipt(&vec![b'x'; MAX_RECEIPT_BYTES + 1]),
        Err(DecodeError::TooLarge)
    );
    let oversized = format!("{}{}", bytes, " ".repeat(MAX_RECEIPT_BYTES));
    assert_eq!(
        decode_receipt(oversized.as_bytes()),
        Err(DecodeError::TooLarge)
    );

    let zero_attempt = bytes.replacen("\"attempt\":1", "\"attempt\":0", 1);
    assert_eq!(
        decode_receipt(zero_attempt.as_bytes()),
        Err(DecodeError::InvalidNumber("attempt"))
    );
    let negative_budget = bytes.replacen("\"reserved_budget\":100", "\"reserved_budget\":-1", 1);
    assert_eq!(
        decode_receipt(negative_budget.as_bytes()),
        Err(DecodeError::NegativeValue("reserved_budget"))
    );
}

#[test]
fn timestamp_and_lifecycle_contradictions_are_rejected() {
    let bytes = canonical();
    let timestamps = bytes.replacen("\"completed_at_ms\":3", "\"completed_at_ms\":1", 1);
    assert_eq!(
        decode_receipt(timestamps.as_bytes()),
        Err(DecodeError::InvalidLifecycle("completed_at_ms"))
    );

    let no_response = bytes.replacen(
        "\"response_digest\":\"sha256:",
        "\"response_digest\":null,\"_unused\":null,\"response_digest_copy\":\"sha256:",
        1,
    );
    assert!(decode_receipt(no_response.as_bytes()).is_err());
}

#[test]
fn provider_reported_negative_cost_is_rejected() {
    let mut receipt = valid_receipt();
    receipt.provider_reported = Some(crate::model_call_receipt::ProviderReportedUsage {
        provider_call_id: "call".into(),
        tokens_in: 1,
        tokens_out: 2,
        provider_cost_micros: 3,
    });
    let bytes = receipt
        .render()
        .replace("\"provider_cost_micros\":3", "\"provider_cost_micros\":-3");
    assert_eq!(
        decode_receipt(bytes.as_bytes()),
        Err(DecodeError::NegativeValue("provider_cost_micros"))
    );
}

#[test]
fn malformed_digest_and_mismatched_report_identity_are_rejected() {
    let bytes = canonical().replace(
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "sha256:NOT-A-DIGEST",
    );
    assert_eq!(
        decode_receipt(bytes.as_bytes()),
        Err(DecodeError::InvalidDigest("request_digest"))
    );

    let mut receipt = valid_receipt();
    receipt.provider_reported = Some(crate::model_call_receipt::ProviderReportedUsage {
        provider_call_id: "provider-call".into(),
        tokens_in: 1,
        tokens_out: 2,
        provider_cost_micros: 3,
    });
    let mismatch = receipt.render();
    assert_eq!(
        decode_receipt(mismatch.as_bytes()),
        Err(DecodeError::InvalidLifecycle("provider_call_reference"))
    );
}

#[test]
fn proposal_fields_require_a_response_and_decoded_requires_admission() {
    let receipt = valid_receipt();
    let with_response = receipt.render();
    let no_response = with_response
        .replace(
            &format!(
                "\"response_digest\":\"{}\"",
                receipt.response_digest.as_ref().unwrap()
            ),
            "\"response_digest\":null",
        )
        .replace("\"response_bytes_len\":13", "\"response_bytes_len\":null");
    assert_eq!(
        decode_receipt(no_response.as_bytes()),
        Err(DecodeError::InvalidLifecycle("proposal_response"))
    );

    let refused_decoded = with_response
        .replace(
            &format!(
                "\"proposal_digest\":\"{}\"",
                receipt.proposal_digest.as_ref().unwrap()
            ),
            "\"proposal_digest\":null",
        )
        .replace(
            "\"proposal_refusal_reason\":null",
            "\"proposal_refusal_reason\":\"refused\"",
        );
    assert_eq!(
        decode_receipt(refused_decoded.as_bytes()),
        Err(DecodeError::InvalidLifecycle("decoded_outcome"))
    );
}
