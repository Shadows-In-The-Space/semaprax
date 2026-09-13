use super::*;
use crate::live_invocation::pricing::{ProviderChargeObservation, ValidatedPricing};
use serde_json::Value;

fn digest_value(label: &str) -> String {
    crate::live_invocation::identity::digest(b"test.priced-v4\0", label.as_bytes())
}

fn binding() -> PricedSourceBindingV4 {
    PricedSourceBindingV4::new(
        digest_value("base"),
        "fixed_model_attempt_units.v1",
        2,
        ValidatedPricing::new(
            "fixed_model_attempt_units.v1".into(),
            "USD".into(),
            6,
            7,
            100,
        )
        .unwrap(),
    )
    .unwrap()
}

fn intent(binding: &PricedSourceBindingV4) -> PricedAttemptIntentV4 {
    let request = digest_value("request");
    let prompt = digest_value("prompt");
    PricedAttemptIntentV4 {
        turn: 3,
        attempt: 1,
        money_ordinal: 4,
        attempt_digest: binding
            .attempt_digest(3, 1, 4, &request, &prompt, 12, 64)
            .unwrap(),
        request_digest: request,
        prompt_digest: prompt,
        request_bytes: 12,
        reserved_units: 2,
        reserved_minor: 14,
        response_limit: 64,
    }
}

#[test]
fn binding_commits_all_integer_pricing_fields_and_exact_work_unit() {
    let base = digest_value("base");
    let price = ValidatedPricing::new(
        "fixed_model_attempt_units.v1".into(),
        "USD".into(),
        6,
        7,
        100,
    )
    .unwrap();
    let binding = PricedSourceBindingV4::new(
        base.clone(),
        "fixed_model_attempt_units.v1",
        2,
        price.clone(),
    )
    .unwrap();
    let changed = PricedSourceBindingV4::new(
        base,
        "fixed_model_attempt_units.v1",
        2,
        ValidatedPricing::new(
            "fixed_model_attempt_units.v1".into(),
            "USD".into(),
            6,
            8,
            100,
        )
        .unwrap(),
    )
    .unwrap();
    assert_ne!(binding.invocation(), changed.invocation());
    assert!(PricedSourceBindingV4::new(digest_value("bad"), "other.v1", 2, price).is_err());
}

#[test]
fn intent_wire_round_trip_rechecks_quote_and_rejects_a_tampered_minor_amount() {
    let binding = binding();
    let intent = intent(&binding);
    let value: Value = serde_json::from_str(&intent.render(7)).unwrap();
    assert_eq!(
        PricedAttemptIntentV4::decode(&value, 7, &binding).unwrap(),
        intent
    );
    let mut tampered = value.as_object().unwrap().clone();
    tampered.insert("reserved_minor".into(), Value::from(13));
    assert!(PricedAttemptIntentV4::decode(&Value::Object(tampered), 7, &binding).is_err());
}

#[test]
fn usage_wire_keeps_unknown_distinct_and_refuses_floating_or_wrong_currency_charge() {
    let binding = binding();
    let unknown = PricedAttemptUsageV4 {
        turn: 3,
        attempt: 1,
        money_ordinal: 4,
        usage: SourceUsageObservationV4::Unknown,
        charge: ProviderChargeObservation::Unknown,
    };
    let value: Value = serde_json::from_str(&unknown.render(8)).unwrap();
    assert_eq!(
        PricedAttemptUsageV4::decode(&value, 8, &binding).unwrap(),
        unknown
    );
    let floating: Value = serde_json::from_str(
        r#"{"seq":8,"kind":"priced_attempt_usage","turn":3,"attempt":1,"money_ordinal":4,"usage":{"kind":"unknown"},"charge":{"kind":"observed","currency":"USD","minor_unit_exponent":6,"amount_minor":1.5}}"#,
    ).unwrap();
    assert!(PricedAttemptUsageV4::decode(&floating, 8, &binding).is_err());
    let wrong = PricedAttemptUsageV4 {
        turn: 3,
        attempt: 1,
        money_ordinal: 4,
        usage: SourceUsageObservationV4::Unknown,
        charge: ProviderChargeObservation::Observed {
            currency: "EUR".into(),
            minor_unit_exponent: 6,
            amount_minor: 1,
        },
    };
    let wrong: Value = serde_json::from_str(&wrong.render(8)).unwrap();
    assert!(PricedAttemptUsageV4::decode(&wrong, 8, &binding).is_err());
}

#[test]
fn journal_fold_replays_observed_overage_without_refund_or_float_inference() {
    let binding = binding();
    let intent = PricedAttemptIntentV4 {
        money_ordinal: 0,
        attempt_digest: binding
            .attempt_digest(
                0,
                0,
                0,
                &digest_value("request"),
                &digest_value("prompt"),
                12,
                64,
            )
            .unwrap(),
        request_digest: digest_value("request"),
        prompt_digest: digest_value("prompt"),
        turn: 0,
        attempt: 0,
        request_bytes: 12,
        reserved_units: 2,
        reserved_minor: 14,
        response_limit: 64,
    };
    let response = Vec::new();
    let entries = vec![
        super::super::SourceJournalEntry::PricedAttemptIntent(intent),
        super::super::SourceJournalEntry::AttemptSettled {
            turn: 0,
            attempt: 0,
            response_digest: super::super::source_response_digest(&response),
            response,
        },
        super::super::SourceJournalEntry::PricedAttemptUsage(PricedAttemptUsageV4 {
            turn: 0,
            attempt: 0,
            money_ordinal: 0,
            usage: SourceUsageObservationV4::Unknown,
            charge: ProviderChargeObservation::Observed {
                currency: "USD".into(),
                minor_unit_exponent: 6,
                amount_minor: 17,
            },
        }),
    ];
    let totals = fold_unmigrated(&binding, &entries).unwrap();
    assert_eq!(totals.reserved_minor, 14);
    assert_eq!(totals.observed_charge_minor, 17);
    assert_eq!(totals.unknown_charge_reservation_minor, 0);
    assert_eq!(totals.observed_over_reservation_minor, 3);
    assert_eq!(totals.remaining_admission_minor, 83);
}

#[test]
fn journal_fold_refuses_usage_that_relabels_an_older_money_ordinal() {
    let binding = binding();
    let request = digest_value("ordinal-request");
    let prompt = digest_value("ordinal-prompt");
    let make_intent = |turn, money_ordinal| PricedAttemptIntentV4 {
        turn,
        attempt: 0,
        money_ordinal,
        attempt_digest: binding
            .attempt_digest(turn, 0, money_ordinal, &request, &prompt, 12, 64)
            .unwrap(),
        request_digest: request.clone(),
        prompt_digest: prompt.clone(),
        request_bytes: 12,
        reserved_units: 2,
        reserved_minor: 14,
        response_limit: 64,
    };
    let response = Vec::new();
    let entries = vec![
        super::super::SourceJournalEntry::PricedAttemptIntent(make_intent(0, 0)),
        super::super::SourceJournalEntry::PricedAttemptIntent(make_intent(1, 1)),
        super::super::SourceJournalEntry::AttemptSettled {
            turn: 1,
            attempt: 0,
            response_digest: super::super::source_response_digest(&response),
            response,
        },
        super::super::SourceJournalEntry::PricedAttemptUsage(PricedAttemptUsageV4 {
            turn: 1,
            attempt: 0,
            money_ordinal: 0,
            usage: SourceUsageObservationV4::Unknown,
            charge: ProviderChargeObservation::Unknown,
        }),
    ];
    assert_eq!(
        fold_unmigrated(&binding, &entries),
        Err(SourceJournalError::Order)
    );
}
