use super::*;

fn priced_profile() -> String {
    let mut profile = parse_profile(&fixture_profile()).unwrap();
    profile.models[0].input_price = 1_000_000;
    profile.limits.max_usd_microunits = 1_000_000;
    render_profile(&profile)
}

fn totals(receipt: &str) -> (u64, u64, u64) {
    let value: Value = serde_json::from_str(receipt.trim_end()).unwrap();
    let totals = value["totals"].as_object().unwrap();
    (
        totals["reserved_usd_microunits"].as_u64().unwrap(),
        totals["observed_usd_microunits"].as_u64().unwrap(),
        totals["unknown_usd_microunits"].as_u64().unwrap(),
    )
}

#[test]
fn accounting_receipt_distinguishes_explicit_zero_or_missing_usage_and_reconciles() {
    let profile = priced_profile();
    let unknown = new_agent(&profile, ScriptHost::final_only("done"))
        .run(&fixture_task())
        .unwrap();
    let (reserved, observed, unknown_exposure) = totals(unknown.accounting_receipt());
    assert!(reserved > 0);
    assert_eq!(observed, 0);
    assert_eq!(unknown_exposure, reserved);
    replay_accounting_receipt(unknown.accounting_receipt(), &unknown).unwrap();
    assert!(unknown.accounting_receipt_digest().starts_with("sha256:"));

    let mut explicit_zero = ScriptHost::final_only("done");
    explicit_zero.attempts[0].2 = ProviderUsage::new(0, 0, 0);
    let explicit_zero = new_agent(&profile, explicit_zero)
        .run(&fixture_task())
        .unwrap();
    let (zero_reserved, zero_observed, zero_unknown) = totals(explicit_zero.accounting_receipt());
    assert_eq!(zero_reserved, reserved);
    assert_eq!(zero_observed, 0);
    assert_eq!(zero_unknown, 0);
    assert!(explicit_zero
        .accounting_receipt()
        .contains("\"kind\":\"observed\",\"usd_microunits\":0"));

    let hostile = unknown.accounting_receipt().replacen(
        "\"status\":\"completed\"",
        "\"status\":\"cancelled\"",
        1,
    );
    assert!(replay_accounting_receipt(&hostile, &unknown).is_err());

    let mut reported = ScriptHost::final_only("unused");
    reported.attempts[0].1 = vec![b"not a canonical action\n".to_vec()];
    reported.attempts[0].2 = ProviderUsage::new(0, 0, reserved);
    let reported = new_agent(&profile, reported).run(&fixture_task()).unwrap();
    assert_eq!(reported.status(), RunStatus::ProviderFailed);
    let (reported_reserved, reported_observed, reported_unknown) =
        totals(reported.accounting_receipt());
    assert_eq!(reported_reserved, reserved);
    assert_eq!(reported_observed, reserved);
    assert_eq!(reported_unknown, 0);
    replay_accounting_receipt(reported.accounting_receipt(), &reported).unwrap();
}
