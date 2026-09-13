use super::*;

fn pricing(ceiling_minor: i64) -> ValidatedPricing {
    ValidatedPricing::new(
        "fixed_model_attempt_units.v1".into(),
        "USD".into(),
        6,
        7,
        ceiling_minor,
    )
    .unwrap()
}

fn observed(amount_minor: i64) -> ProviderChargeObservation {
    ProviderChargeObservation::Observed {
        currency: "USD".into(),
        minor_unit_exponent: 6,
        amount_minor,
    }
}

#[test]
fn contract_requires_exact_static_bindings_and_checked_quote_inputs() {
    assert_eq!(
        ValidatedPricing::new("bad space".into(), "USD".into(), 6, 1, 0),
        Err(PricingConfigError::InvalidWorkUnit)
    );
    assert_eq!(
        ValidatedPricing::new("unit.v1".into(), "usd".into(), 6, 1, 0),
        Err(PricingConfigError::InvalidCurrency)
    );
    assert_eq!(
        ValidatedPricing::new("unit.v1".into(), "USD".into(), 10, 1, 0),
        Err(PricingConfigError::InvalidMinorUnitExponent)
    );
    assert_eq!(
        ValidatedPricing::new("unit.v1".into(), "USD".into(), 6, 0, 0),
        Err(PricingConfigError::NonPositiveQuote)
    );
    assert_eq!(
        ValidatedPricing::new("unit.v1".into(), "USD".into(), 6, 1, -1),
        Err(PricingConfigError::NegativeCeiling)
    );
    let contract = pricing(i64::MAX);
    assert_eq!(
        contract.quote("other.v1", 1).unwrap_err().0,
        PRICING_UNIT_MISMATCH
    );
    assert_eq!(
        contract.quote(contract.work_unit(), -1).unwrap_err().0,
        PRICING_NEGATIVE_WORK
    );
    assert_eq!(
        contract.quote(contract.work_unit(), 0).unwrap_err().0,
        PRICING_ZERO_WORK
    );
    assert_eq!(
        contract
            .quote(contract.work_unit(), i64::MAX)
            .unwrap_err()
            .0,
        PRICING_PRODUCT_OVERFLOW
    );
}

#[test]
fn reserves_exact_boundary_and_never_refunds_settled_observations() {
    let mut accounting = MonetaryAccounting::new(pricing(14));
    let first = accounting
        .reserve("fixed_model_attempt_units.v1", 1)
        .unwrap();
    let second = accounting
        .reserve("fixed_model_attempt_units.v1", 1)
        .unwrap();
    assert_eq!(accounting.reserved_minor(), 14);
    assert_eq!(accounting.unknown_reservation_minor(), 14);
    assert_eq!(
        accounting
            .reserve("fixed_model_attempt_units.v1", 1)
            .unwrap_err()
            .0,
        PRICING_BUDGET_EXHAUSTED
    );
    accounting.record_charge(first, observed(1)).unwrap();
    accounting.record_charge(second, observed(7)).unwrap();
    assert_eq!(accounting.reserved_minor(), 14);
    assert_eq!(accounting.observed_minor(), 8);
    assert_eq!(accounting.unknown_reservation_minor(), 0);
    assert_eq!(accounting.conservative_exposure_minor().unwrap(), 14);
}

#[test]
fn unknown_is_explicit_and_overage_increases_conservative_exposure() {
    let mut accounting = MonetaryAccounting::new(pricing(14));
    let unknown = accounting
        .reserve("fixed_model_attempt_units.v1", 1)
        .unwrap();
    let over = accounting
        .reserve("fixed_model_attempt_units.v1", 1)
        .unwrap();
    accounting
        .record_charge(unknown, ProviderChargeObservation::Unknown)
        .unwrap();
    accounting.record_charge(over, observed(11)).unwrap();
    assert_eq!(accounting.unknown_reservation_minor(), 7);
    assert_eq!(accounting.observed_over_reservation_minor(), 4);
    assert_eq!(accounting.conservative_exposure_minor().unwrap(), 18);
}

#[test]
fn observed_overage_refuses_the_next_reservation_without_erasing_the_overage() {
    let mut accounting = MonetaryAccounting::new(pricing(14));
    let first = accounting
        .reserve("fixed_model_attempt_units.v1", 1)
        .unwrap();
    accounting.record_charge(first, observed(15)).unwrap();
    assert_eq!(accounting.reserved_minor(), 7);
    assert_eq!(accounting.observed_over_reservation_minor(), 8);
    assert_eq!(accounting.conservative_exposure_minor().unwrap(), 15);
    assert_eq!(
        accounting
            .reserve("fixed_model_attempt_units.v1", 1)
            .unwrap_err()
            .0,
        PRICING_BUDGET_EXHAUSTED
    );
    assert_eq!(accounting.attempts().len(), 1);
    assert_eq!(accounting.observed_minor(), 15);
}

#[test]
fn rejects_invalid_observation_before_mutating_the_attempt() {
    let mut accounting = MonetaryAccounting::new(pricing(7));
    let reservation = accounting
        .reserve("fixed_model_attempt_units.v1", 1)
        .unwrap();
    let mismatch = ProviderChargeObservation::Observed {
        currency: "EUR".into(),
        minor_unit_exponent: 6,
        amount_minor: 1,
    };
    assert_eq!(
        accounting
            .record_charge(reservation, mismatch)
            .unwrap_err()
            .0,
        PRICING_CURRENCY_MISMATCH
    );
    assert_eq!(accounting.unknown_reservation_minor(), 7);
    assert_eq!(
        accounting
            .record_charge(
                reservation,
                ProviderChargeObservation::Observed {
                    currency: "USD".into(),
                    minor_unit_exponent: 6,
                    amount_minor: -1
                }
            )
            .unwrap_err()
            .0,
        PRICING_NEGATIVE_OBSERVATION
    );
    assert_eq!(accounting.unknown_reservation_minor(), 7);
}

#[test]
fn resume_recomputes_reserved_unknown_and_observed_values_from_attempts() {
    let contract = pricing(14);
    let first = MonetaryReservation::recover(&contract, 0, 1, 7).unwrap();
    let second = MonetaryReservation::recover(&contract, 1, 1, 7).unwrap();
    let recovered = MonetaryAccounting::resume(
        contract,
        &[
            MonetaryAttempt {
                reservation: first,
                charge: ProviderChargeObservation::Unknown,
            },
            MonetaryAttempt {
                reservation: second,
                charge: observed(9),
            },
        ],
    )
    .unwrap();
    assert_eq!(recovered.reserved_minor(), 14);
    assert_eq!(recovered.observed_minor(), 9);
    assert_eq!(recovered.unknown_reservation_minor(), 7);
    assert_eq!(recovered.observed_over_reservation_minor(), 2);
    assert_eq!(recovered.conservative_exposure_minor().unwrap(), 16);
}

#[test]
fn resume_preserves_terminal_overage_but_refuses_a_new_reservation() {
    let contract = pricing(14);
    let first = MonetaryReservation::recover(&contract, 0, 1, 7).unwrap();
    let recovered = MonetaryAccounting::resume(
        contract,
        &[MonetaryAttempt {
            reservation: first,
            charge: observed(15),
        }],
    )
    .unwrap();
    assert_eq!(recovered.reserved_minor(), 7);
    assert_eq!(recovered.observed_minor(), 15);
    assert_eq!(recovered.observed_over_reservation_minor(), 8);
    assert_eq!(recovered.conservative_exposure_minor().unwrap(), 15);
    let mut recovered = recovered;
    assert_eq!(
        recovered
            .reserve("fixed_model_attempt_units.v1", 1)
            .unwrap_err()
            .0,
        PRICING_BUDGET_EXHAUSTED
    );
}

#[test]
fn priced_carry_preserves_ordinal_and_overage_while_only_allowing_narrowing() {
    let carry = PricedMonetaryCarry::from_validated(pricing(21), 7, 15, 0, 8, 3).unwrap();
    let mut recovered =
        MonetaryAccounting::resume_with_priced_carry(pricing(14), carry.clone(), &[]).unwrap();
    assert_eq!(
        recovered
            .reserve("fixed_model_attempt_units.v1", 1)
            .unwrap_err()
            .0,
        PRICING_BUDGET_EXHAUSTED
    );
    assert_eq!(
        carry.validate_destination(&pricing(22)).unwrap_err().0,
        PRICING_BUDGET_EXHAUSTED
    );
    assert!(carry.validate_destination(&pricing(7)).is_ok());
    assert_eq!(
        carry.validate_destination(&pricing(6)).unwrap_err().0,
        PRICING_BUDGET_EXHAUSTED
    );
    let ordinary = PricedMonetaryCarry::from_validated(pricing(21), 7, 0, 7, 0, 3).unwrap();
    let mut ordinary =
        MonetaryAccounting::resume_with_priced_carry(pricing(21), ordinary, &[]).unwrap();
    assert_eq!(
        ordinary
            .reserve("fixed_model_attempt_units.v1", 1)
            .unwrap()
            .ordinal(),
        3
    );
}

#[test]
fn exhausted_global_ordinal_refuses_without_mutating_accounting() {
    let carry = PricedMonetaryCarry::from_validated(pricing(14), 0, 0, 0, 0, u32::MAX).unwrap();
    let mut accounting =
        MonetaryAccounting::resume_with_priced_carry(pricing(14), carry, &[]).unwrap();
    assert_eq!(
        accounting
            .reserve("fixed_model_attempt_units.v1", 1)
            .unwrap_err()
            .0,
        PRICING_TOTAL_OVERFLOW
    );
    assert_eq!(accounting.reserved_minor(), 0);
    assert_eq!(accounting.unknown_reservation_minor(), 0);
    assert!(accounting.attempts().is_empty());
    assert_eq!(accounting.failure(), None);
}

#[test]
fn replay_restores_a_terminal_overage_but_rejects_a_later_forged_intent() {
    let contract = pricing(10);
    let first = MonetaryReservation::recover(&contract, 0, 1, 7).unwrap();
    let terminal = MonetaryAccounting::resume(
        contract.clone(),
        &[MonetaryAttempt {
            reservation: first,
            charge: observed(100),
        }],
    )
    .expect("a historical terminal overage remains representable");
    assert_eq!(terminal.observed_over_reservation_minor(), 93);

    let second = MonetaryReservation::recover(&contract, 1, 1, 7).unwrap();
    assert_eq!(
        MonetaryAccounting::resume(
            contract,
            &[
                MonetaryAttempt {
                    reservation: first,
                    charge: observed(100),
                },
                MonetaryAttempt {
                    reservation: second,
                    charge: ProviderChargeObservation::Unknown,
                },
            ],
        )
        .unwrap_err()
        .0,
        PRICING_BUDGET_EXHAUSTED
    );
}

#[test]
fn legacy_carry_is_unknown_exposure_without_a_fabricated_v4_attempt() {
    let contract = pricing(21);
    let carry = MonetaryCarry::from_legacy_work(&contract, 2).unwrap();
    let mut accounting = MonetaryAccounting::with_legacy_carry(contract, carry).unwrap();
    assert_eq!(accounting.attempts(), &[]);
    assert_eq!(accounting.reserved_minor(), 14);
    assert_eq!(accounting.unknown_reservation_minor(), 14);
    accounting
        .reserve("fixed_model_attempt_units.v1", 1)
        .expect("carry plus one exact quote fits");
    assert_eq!(
        accounting
            .reserve("fixed_model_attempt_units.v1", 1)
            .unwrap_err()
            .0,
        PRICING_BUDGET_EXHAUSTED
    );
}

#[test]
fn resumed_v4_attempt_ordinals_start_after_a_legacy_carry_without_rewriting_it() {
    let contract = pricing(21);
    let carry = MonetaryCarry::from_legacy_work(&contract, 1).unwrap();
    let first_v4 = MonetaryReservation::recover(&contract, 0, 1, 7).unwrap();
    let resumed = MonetaryAccounting::resume_with_legacy_carry(
        contract,
        Some(carry),
        &[MonetaryAttempt {
            reservation: first_v4,
            charge: ProviderChargeObservation::Unknown,
        }],
    )
    .unwrap();
    assert_eq!(resumed.attempts().len(), 1);
    assert_eq!(resumed.attempts()[0].reservation.ordinal(), 0);
    assert_eq!(resumed.reserved_minor(), 14);
    assert_eq!(resumed.unknown_reservation_minor(), 14);
}

#[test]
fn legacy_carry_rechecks_its_exact_operator_price_identity() {
    let source = pricing(21);
    let carry = MonetaryCarry::from_legacy_work(&source, 1).unwrap();
    let changed_rate = ValidatedPricing::new(
        "fixed_model_attempt_units.v1".into(),
        "USD".into(),
        6,
        8,
        21,
    )
    .unwrap();
    assert_eq!(
        MonetaryAccounting::with_legacy_carry(changed_rate, carry)
            .unwrap_err()
            .0,
        PRICING_RATE_MISMATCH
    );
}

#[test]
fn zero_legacy_work_is_a_valid_zero_exposure_migration_baseline() {
    let contract = pricing(0);
    let carry = MonetaryCarry::from_legacy_work(&contract, 0).unwrap();
    let accounting = MonetaryAccounting::with_legacy_carry(contract, carry).unwrap();
    assert_eq!(accounting.reserved_minor(), 0);
    assert_eq!(accounting.unknown_reservation_minor(), 0);
    assert!(accounting.attempts().is_empty());
}

#[test]
fn zero_work_never_allocates_an_attempt_and_attempts_are_bounded() {
    let mut accounting = MonetaryAccounting::new(pricing(100));
    assert_eq!(accounting.attempts.capacity(), 0);
    assert_eq!(
        accounting
            .reserve("fixed_model_attempt_units.v1", 0)
            .unwrap_err()
            .0,
        PRICING_ZERO_WORK
    );
    assert!(accounting.attempts().is_empty());
    let reservation = MonetaryReservation::recover(accounting.pricing(), 0, 1, 7).unwrap();
    accounting.attempts = vec![
        MonetaryAttempt {
            reservation,
            charge: ProviderChargeObservation::Unknown,
        };
        MAX_SOURCE_ENTRIES
    ];
    assert_eq!(
        accounting
            .reserve("fixed_model_attempt_units.v1", 1)
            .unwrap_err()
            .0,
        PRICING_ATTEMPT_CAPACITY
    );
}

#[test]
fn observation_overflow_fails_stopped_and_retains_unknown_exposure() {
    let mut accounting = MonetaryAccounting::new(pricing(i64::MAX));
    let first = accounting
        .reserve("fixed_model_attempt_units.v1", 1)
        .unwrap();
    let second = accounting
        .reserve("fixed_model_attempt_units.v1", 1)
        .unwrap();
    accounting.record_charge(first, observed(i64::MAX)).unwrap();
    assert_eq!(accounting.unknown_reservation_minor(), 7);
    assert_eq!(
        accounting.record_charge(second, observed(1)).unwrap_err().0,
        PRICING_TOTAL_OVERFLOW
    );
    assert_eq!(accounting.failure(), Some(PRICING_TOTAL_OVERFLOW));
    assert_eq!(accounting.unknown_reservation_minor(), 7);
    assert!(matches!(
        &accounting.attempts()[1].charge,
        ProviderChargeObservation::Unknown
    ));
    assert_eq!(
        accounting
            .reserve("fixed_model_attempt_units.v1", 1)
            .unwrap_err()
            .0,
        PRICING_TOTAL_OVERFLOW
    );
}

#[test]
fn resume_refuses_tampered_quote_or_nonsequential_ordinal() {
    let contract = pricing(7);
    let tampered = MonetaryAttempt {
        reservation: MonetaryReservation {
            ordinal: 0,
            work_units: 1,
            reserved_minor: 6,
        },
        charge: ProviderChargeObservation::Unknown,
    };
    assert_eq!(
        MonetaryAccounting::resume(contract.clone(), &[tampered])
            .unwrap_err()
            .0,
        PRICING_UNIT_MISMATCH
    );
    let skipped = MonetaryAttempt {
        reservation: MonetaryReservation::recover(&contract, 1, 1, 7).unwrap(),
        charge: ProviderChargeObservation::Unknown,
    };
    assert_eq!(
        MonetaryAccounting::resume(contract, &[skipped])
            .unwrap_err()
            .0,
        PRICING_UNKNOWN_RESERVATION
    );
}
