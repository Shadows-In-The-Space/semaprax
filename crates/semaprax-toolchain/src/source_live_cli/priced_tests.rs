use super::*;

#[test]
fn priced_cli_run_and_resume_preserve_unknown_charge_without_redispatch() {
    let fixture = Fixture::new();
    let manifest = source_project(
        &fixture.0.join("project"),
        source_fixture::SOURCE,
        "fixture.agent.type.state",
    );
    let config = source_config(&fixture, &manifest);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    value["schema"] = serde_json::json!("semaprax.source-live-cli.config.v2");
    value["pricing"] = serde_json::json!({"currency":"USD", "minor_unit_exponent":6, "price_per_work_unit_minor":7, "money_ceiling_minor":7});
    fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
    let answer = recorded_answer(&manifest);
    let checkpoint = fixture.0.join("checkpoint");
    let calls = Rc::new(Cell::new(0));
    let first = super::super::run::execute_with_runner(
        run_command("run", &config, &checkpoint, &fixture.0.join("scratch-1")),
        runner(answer.clone(), &calls),
    )
    .unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(receipt["schema"], "semaprax.source-live-cli.receipt.v2");
    assert_eq!(receipt["status"], "complete");
    assert_eq!(receipt["committed_model_units"], 1);
    assert_eq!(
        receipt["money"],
        serde_json::json!({
            "currency":"USD", "minor_unit_exponent":6, "reserved_minor":7,
            "observed_charge_minor":0, "unknown_charge_reservation_minor":7,
            "observed_over_reservation_minor":0, "remaining_admission_minor":0
        })
    );
    assert_eq!(calls.get(), 1);
    let before = fs::read(checkpoint.join("checkpoint.json")).unwrap();
    let resumed = super::super::run::execute_with_runner(
        run_command("resume", &config, &checkpoint, &fixture.0.join("scratch-2")),
        runner(answer.clone(), &calls),
    )
    .unwrap();
    let resumed: serde_json::Value = serde_json::from_str(&resumed).unwrap();
    assert_eq!(resumed["money"], receipt["money"]);
    assert_eq!(resumed["generation"], receipt["generation"]);
    assert_eq!(resumed["model_dispatches"], 0);
    assert_eq!(resumed["effect_dispatches"], 0);
    assert_eq!(calls.get(), 1);
    assert_eq!(
        fs::read(checkpoint.join("checkpoint.json")).unwrap(),
        before
    );
    value["pricing"]["price_per_work_unit_minor"] = serde_json::json!(8);
    fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(super::super::run::execute_with_runner(
        run_command("resume", &config, &checkpoint, &fixture.0.join("scratch-3")),
        runner(answer, &calls),
    )
    .is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(
        fs::read(checkpoint.join("checkpoint.json")).unwrap(),
        before
    );
}

#[test]
fn malformed_priced_cli_attempt_retains_charge_in_failure_and_terminal_resume() {
    let fixture = Fixture::new();
    let manifest = source_project(
        &fixture.0.join("project"),
        source_fixture::SOURCE,
        "fixture.agent.type.state",
    );
    let config = source_config(&fixture, &manifest);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    value["schema"] = serde_json::json!("semaprax.source-live-cli.config.v2");
    value["pricing"] = serde_json::json!({"currency":"USD", "minor_unit_exponent":6, "price_per_work_unit_minor":7, "money_ceiling_minor":7});
    fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
    let checkpoint = fixture.0.join("checkpoint");
    let calls = Rc::new(Cell::new(0));
    let failed = super::super::run::execute_with_runner(
        run_command("run", &config, &checkpoint, &fixture.0.join("scratch-1")),
        runner("not-json".into(), &calls),
    )
    .unwrap_err();
    assert!(
        failed.reason.contains("reserved_minor=7"),
        "{}",
        failed.reason
    );
    assert!(
        failed.reason.contains("unknown_charge_reservation_minor=7"),
        "{}",
        failed.reason
    );
    assert_eq!(calls.get(), 1);
    let before = fs::read(checkpoint.join("checkpoint.json")).unwrap();
    let resumed = super::super::run::execute_with_runner(
        run_command("resume", &config, &checkpoint, &fixture.0.join("scratch-2")),
        runner("not-json".into(), &calls),
    )
    .unwrap();
    let resumed: serde_json::Value = serde_json::from_str(&resumed).unwrap();
    assert_ne!(resumed["status"], "complete");
    assert_eq!(resumed["money"]["reserved_minor"], 7);
    assert_eq!(resumed["money"]["unknown_charge_reservation_minor"], 7);
    assert_eq!(resumed["model_dispatches"], 0);
    assert_eq!(calls.get(), 1);
    assert_eq!(
        fs::read(checkpoint.join("checkpoint.json")).unwrap(),
        before
    );
}
