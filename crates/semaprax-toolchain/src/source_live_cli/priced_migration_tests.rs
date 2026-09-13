use super::*;

fn price(path: &std::path::Path, ceiling: i64) {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    value["schema"] = serde_json::json!("semaprax.source-live-cli.config.v2");
    value["pricing"] = serde_json::json!({"currency":"USD", "minor_unit_exponent":6, "price_per_work_unit_minor":7, "money_ceiling_minor":ceiling});
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

#[test]
fn priced_migration_carries_unknown_exposure_and_narrowed_ceiling_without_refund() {
    for (ceiling, destination_calls, reserved) in [(7, 0, 7), (14, 1, 14), (15, 1, 14)] {
        let fixture = Fixture::new();
        let suspend_source = source_fixture::SOURCE.replace(
            "Step::Complete { summary: state.objective, budget: state.budget, status: state.epoch }",
            "Step::Suspend { objective: state.objective, budget: state.budget, epoch: state.epoch }",
        );
        assert_ne!(suspend_source, source_fixture::SOURCE);
        let old_manifest = source_project(
            &fixture.0.join("project-a"),
            &suspend_source,
            "fixture.agent.type.state",
        );
        let config = source_config(&fixture, &old_manifest);
        price(&config, 21);
        let old_config = fixture.0.join("config-a.json");
        fs::rename(config, &old_config).unwrap();
        let old_checkpoint = fixture.0.join("checkpoint-a");
        let old_calls = Rc::new(Cell::new(0));
        let suspended = super::super::run::execute_with_runner(
            run_command(
                "run",
                &old_config,
                &old_checkpoint,
                &fixture.0.join("scratch-a"),
            ),
            runner(recorded_answer(&old_manifest), &old_calls),
        )
        .unwrap();
        let first: serde_json::Value = serde_json::from_str(&suspended).unwrap();
        assert_eq!(first["status"], "suspend");
        assert_eq!(first["money"]["reserved_minor"], 7);
        assert_eq!(old_calls.get(), 1);

        let new_manifest = source_project(
            &fixture.0.join("project-b"),
            &successor_source(),
            "fixture.agent.type.state_b",
        );
        let new_config = source_config(&fixture, &new_manifest);
        price(&new_config, ceiling);
        let new_checkpoint = fixture.0.join("checkpoint-b");
        let new_calls = Rc::new(Cell::new(0));
        let answer = recorded_answer(&new_manifest);
        let result = super::super::run::execute_with_runner(
            migrate_command(
                &old_config,
                &old_checkpoint,
                &new_config,
                &new_checkpoint,
                &fixture.0.join("scratch-b"),
            ),
            runner(answer.clone(), &new_calls),
        );
        if destination_calls == 0 {
            let error = result.unwrap_err();
            assert!(
                error.reason.contains("selected=budget_exhausted"),
                "{}",
                error.reason
            );
            assert!(
                error.reason.contains("reserved_minor=7"),
                "{}",
                error.reason
            );
        } else {
            let receipt: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
            assert_eq!(receipt["status"], "complete");
            assert_eq!(receipt["money"]["reserved_minor"], reserved);
        }
        assert_eq!(new_calls.get(), destination_calls);
        let before = fs::read(new_checkpoint.join("checkpoint.json")).unwrap();
        let replay = super::super::run::execute_with_runner(
            migrate_command(
                &old_config,
                &old_checkpoint,
                &new_config,
                &new_checkpoint,
                &fixture.0.join("scratch-c"),
            ),
            runner(answer, &new_calls),
        )
        .unwrap();
        let replay: serde_json::Value = serde_json::from_str(&replay).unwrap();
        assert_eq!(
            replay["status"],
            if destination_calls == 0 {
                "budget_exhausted"
            } else {
                "complete"
            }
        );
        assert_eq!(replay["committed_model_units"], destination_calls + 1);
        assert_eq!(replay["money"]["reserved_minor"], reserved);
        assert_eq!(
            replay["money"]["unknown_charge_reservation_minor"],
            reserved
        );
        assert_eq!(replay["money"]["observed_charge_minor"], 0);
        assert_eq!(replay["model_dispatches"], 0);
        assert_eq!(replay["effect_dispatches"], 0);
        assert_eq!(new_calls.get(), destination_calls);
        assert_eq!(
            fs::read(new_checkpoint.join("checkpoint.json")).unwrap(),
            before
        );
    }
}
