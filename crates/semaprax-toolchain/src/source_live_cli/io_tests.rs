use super::*;

use crate::opencode_host::{OpenCodeHostConfig, OpenCodeRunner, OpenCodeRunnerFailure};

struct SequenceRunner {
    answers: Vec<String>,
    next: usize,
    last: Option<String>,
    prompt: String,
    calls: Rc<Cell<usize>>,
}

impl OpenCodeRunner for SequenceRunner {
    fn run(
        &mut self,
        _: &OpenCodeHostConfig,
        prompt: &str,
    ) -> Result<Vec<u8>, OpenCodeRunnerFailure> {
        let answer = self.answers[self.next].clone();
        self.next += 1;
        self.last = Some(answer.clone());
        self.prompt = prompt.to_owned();
        self.calls.set(self.calls.get() + 1);
        Ok(recorded_transport(prompt, &answer).0)
    }

    fn export(
        &mut self,
        _: &OpenCodeHostConfig,
        _: &str,
    ) -> Result<Vec<u8>, OpenCodeRunnerFailure> {
        Ok(recorded_transport(&self.prompt, self.last.as_deref().unwrap()).1)
    }
}

fn io_config(path: &std::path::Path, request: usize, total_request: u64, total_response: u64) {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    value["schema"] = serde_json::json!("semaprax.source-live-cli.config.v3");
    value["pricing"] = serde_json::json!({
        "currency":"USD", "minor_unit_exponent":6,
        "price_per_work_unit_minor":7, "money_ceiling_minor":14,
    });
    value["io_limits"] = serde_json::json!({
        "max_request_bytes": request,
        "max_total_request_bytes": total_request,
        "max_total_response_bytes": total_response,
    });
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn io_rows(checkpoint: &std::path::Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(checkpoint.join("checkpoint.json")).unwrap()).unwrap()
}

#[test]
fn io_response_reservation_is_exact_or_refuses_the_retry_before_transport() {
    for (total_response, expected_calls, complete) in [(8192, 2, true), (8191, 1, false)] {
        let fixture = Fixture::new();
        let manifest = source_project(
            &fixture.0.join("project"),
            source_fixture::SOURCE,
            "fixture.agent.type.state",
        );
        let config = source_config(&fixture, &manifest);
        io_config(&config, 65_536, 131_072, total_response);
        let checkpoint = fixture.0.join("checkpoint");
        let calls = Rc::new(Cell::new(0));
        let result = crate::source_live_cli::run::execute_with_runner(
            run_command("run", &config, &checkpoint, &fixture.0.join("scratch")),
            SequenceRunner {
                answers: vec!["not-json\n".into(), recorded_answer(&manifest)],
                next: 0,
                last: None,
                prompt: String::new(),
                calls: calls.clone(),
            },
        );
        assert_eq!(
            calls.get(),
            expected_calls,
            "response ceiling {total_response}"
        );
        if complete {
            let receipt: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
            assert_eq!(receipt["schema"], "semaprax.source-live-cli.receipt.v3");
            assert_eq!(receipt["io"]["reserved_response_bytes"], 8192);
        } else {
            let error = result.unwrap_err();
            assert!(
                error.reason.contains("selected=budget_exhausted"),
                "{}",
                error.reason
            );
            assert!(
                error.reason.contains("reserved_response_bytes=4096"),
                "{}",
                error.reason
            );
        }
    }
}

#[test]
fn io_request_cap_zero_exact_resume_and_binding_drift_do_not_dispatch() {
    let fixture = Fixture::new();
    let manifest = source_project(
        &fixture.0.join("project"),
        source_fixture::SOURCE,
        "fixture.agent.type.state",
    );
    let config = source_config(&fixture, &manifest);
    let checkpoint = fixture.0.join("checkpoint");

    io_config(&config, 0, 65_536, 4096);
    let zero_calls = Rc::new(Cell::new(0));
    assert!(crate::source_live_cli::run::execute_with_runner(
        run_command("run", &config, &checkpoint, &fixture.0.join("zero")),
        runner(recorded_answer(&manifest), &zero_calls),
    )
    .is_err());
    assert_eq!(zero_calls.get(), 0);
    let zero_rows = io_rows(&checkpoint);
    assert!(zero_rows["entries"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["kind"] != "priced_attempt_intent"));
    // The failed run has an acknowledged initialization/terminal history;
    // the independent exact-cap run gets its own empty store.
    let checkpoint = fixture.0.join("exact-checkpoint");

    // A wide, independent run reveals the exact canonical prompt debit. The
    // subsequent fresh checkpoint admits precisely that one request.
    let probe_checkpoint = fixture.0.join("probe-checkpoint");
    io_config(&config, 65_536, 65_536, 4096);
    let probe_calls = Rc::new(Cell::new(0));
    crate::source_live_cli::run::execute_with_runner(
        run_command("run", &config, &probe_checkpoint, &fixture.0.join("probe")),
        runner(recorded_answer(&manifest), &probe_calls),
    )
    .unwrap();
    let prompt_bytes = io_rows(&probe_checkpoint)["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["kind"] == "priced_attempt_intent")
        .unwrap()["request_bytes"]
        .as_u64()
        .unwrap();

    for (name, request, total) in [
        ("per-request-short", prompt_bytes as usize - 1, prompt_bytes),
        (
            "total-request-short",
            prompt_bytes as usize,
            prompt_bytes - 1,
        ),
    ] {
        io_config(&config, request, total, 4096);
        let refused_checkpoint = fixture.0.join(name);
        let calls = Rc::new(Cell::new(0));
        let error = crate::source_live_cli::run::execute_with_runner(
            run_command(
                "run",
                &config,
                &refused_checkpoint,
                &fixture.0.join(format!("{name}-scratch")),
            ),
            runner(recorded_answer(&manifest), &calls),
        )
        .unwrap_err();
        assert!(
            error.reason.contains("selected=budget_exhausted"),
            "{}",
            error.reason
        );
        assert_eq!(calls.get(), 0);
        assert!(io_rows(&refused_checkpoint)["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["kind"] != "priced_attempt_intent"));
    }
    io_config(&config, prompt_bytes as usize, prompt_bytes, 4096);
    let calls = Rc::new(Cell::new(0));
    let first = crate::source_live_cli::run::execute_with_runner(
        run_command("run", &config, &checkpoint, &fixture.0.join("exact")),
        runner(recorded_answer(&manifest), &calls),
    )
    .unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(receipt["io"]["reserved_request_bytes"], prompt_bytes);
    assert_eq!(calls.get(), 1);
    let before = fs::read(checkpoint.join("checkpoint.json")).unwrap();
    let resumed = crate::source_live_cli::run::execute_with_runner(
        run_command("resume", &config, &checkpoint, &fixture.0.join("resume")),
        runner(recorded_answer(&manifest), &calls),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&resumed).unwrap()["io"],
        receipt["io"]
    );
    assert_eq!(calls.get(), 1);

    io_config(&config, prompt_bytes as usize + 1, prompt_bytes + 1, 4096);
    assert!(crate::source_live_cli::run::execute_with_runner(
        run_command("resume", &config, &checkpoint, &fixture.0.join("drift")),
        runner(recorded_answer(&manifest), &calls),
    )
    .is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(
        fs::read(checkpoint.join("checkpoint.json")).unwrap(),
        before
    );
}

#[test]
fn io_migration_carries_reservations_and_replay_does_not_dispatch() {
    let fixture = Fixture::new();
    let suspended_source = source_fixture::SOURCE.replace(
        "Step::Complete { summary: state.objective, budget: state.budget, status: state.epoch }",
        "Step::Suspend { objective: state.objective, budget: state.budget, epoch: state.epoch }",
    );
    let old_manifest = source_project(
        &fixture.0.join("project-a"),
        &suspended_source,
        "fixture.agent.type.state",
    );
    let old_config = source_config(&fixture, &old_manifest);
    io_config(&old_config, 65_536, 131_072, 8192);
    let saved_old_config = fixture.0.join("config-a.json");
    fs::rename(&old_config, &saved_old_config).unwrap();
    let old_config = saved_old_config;
    let old_checkpoint = fixture.0.join("checkpoint-a");
    let old_calls = Rc::new(Cell::new(0));
    let first = crate::source_live_cli::run::execute_with_runner(
        run_command(
            "run",
            &old_config,
            &old_checkpoint,
            &fixture.0.join("scratch-a"),
        ),
        runner(recorded_answer(&old_manifest), &old_calls),
    )
    .unwrap();
    let first: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(first["status"], "suspend");
    assert_eq!(first["io"]["reserved_response_bytes"], 4096);
    assert_eq!(old_calls.get(), 1);

    let new_manifest = source_project(
        &fixture.0.join("project-b"),
        &successor_source(),
        "fixture.agent.type.state_b",
    );
    let new_config = source_config(&fixture, &new_manifest);
    io_config(&new_config, 65_536, 131_072, 8192);
    let new_checkpoint = fixture.0.join("checkpoint-b");
    let new_calls = Rc::new(Cell::new(0));
    let answer = recorded_answer(&new_manifest);
    let migrated = crate::source_live_cli::run::execute_with_runner(
        migrate_command(
            &old_config,
            &old_checkpoint,
            &new_config,
            &new_checkpoint,
            &fixture.0.join("scratch-b"),
        ),
        runner(answer.clone(), &new_calls),
    )
    .unwrap();
    let migrated: serde_json::Value = serde_json::from_str(&migrated).unwrap();
    assert_eq!(migrated["status"], "complete");
    assert_eq!(migrated["io"]["reserved_response_bytes"], 8192);
    assert_eq!(new_calls.get(), 1);
    let before = fs::read(new_checkpoint.join("checkpoint.json")).unwrap();
    let replay = crate::source_live_cli::run::execute_with_runner(
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
    assert_eq!(replay["io"], migrated["io"]);
    assert_eq!(replay["model_dispatches"], 0);
    assert_eq!(new_calls.get(), 1);
    assert_eq!(
        fs::read(new_checkpoint.join("checkpoint.json")).unwrap(),
        before
    );
}
