use super::*;

use crate::opencode_host::{OpenCodeHostConfig, OpenCodeRunner, OpenCodeRunnerFailure};

struct SequencedRecordedRunner {
    answers: Vec<String>,
    next: usize,
    last_answer: Option<String>,
    prompts: Rc<RefCell<Vec<String>>>,
    calls: Rc<Cell<usize>>,
}

impl OpenCodeRunner for SequencedRecordedRunner {
    fn run(
        &mut self,
        _: &OpenCodeHostConfig,
        prompt: &str,
    ) -> Result<Vec<u8>, OpenCodeRunnerFailure> {
        let answer = self
            .answers
            .get(self.next)
            .expect("scripted response")
            .clone();
        self.next += 1;
        self.last_answer = Some(answer.clone());
        self.calls.set(self.calls.get() + 1);
        self.prompts.borrow_mut().push(prompt.to_owned());
        Ok(recorded_transport(prompt, &answer).0)
    }

    fn export(
        &mut self,
        _: &OpenCodeHostConfig,
        _: &str,
    ) -> Result<Vec<u8>, OpenCodeRunnerFailure> {
        let prompt = self
            .prompts
            .borrow()
            .last()
            .expect("run before export")
            .clone();
        Ok(recorded_transport(&prompt, self.last_answer.as_deref().expect("answer")).1)
    }
}

fn price_config(
    path: &std::path::Path,
    price: serde_json::Value,
    ceiling: serde_json::Value,
    currency: &str,
) {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    value["schema"] = serde_json::json!("semaprax.source-live-cli.config.v2");
    value["pricing"] = serde_json::json!({
        "currency": currency,
        "minor_unit_exponent": 6,
        "price_per_work_unit_minor": price,
        "money_ceiling_minor": ceiling,
    });
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

#[test]
fn priced_adapter_binds_canonical_context_prompt_and_recorded_response() {
    let fixture = Fixture::new();
    let manifest = source_project(
        &fixture.0.join("project"),
        source_fixture::SOURCE,
        "fixture.agent.type.state",
    );
    let config = source_config(&fixture, &manifest);
    price_config(&config, serde_json::json!(7), serde_json::json!(7), "USD");
    let checkpoint = fixture.0.join("checkpoint");
    let calls = Rc::new(Cell::new(0));
    let prompts = Rc::new(RefCell::new(Vec::new()));
    let answer = recorded_answer(&manifest);
    let receipt = super::super::run::execute_with_runner(
        run_command("run", &config, &checkpoint, &fixture.0.join("scratch")),
        SequencedRecordedRunner {
            answers: vec![answer],
            next: 0,
            last_answer: None,
            prompts: prompts.clone(),
            calls: calls.clone(),
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 1);
    let prompt = prompts
        .borrow()
        .first()
        .expect("one provider prompt")
        .clone();
    assert!(prompt.starts_with("SEMAPRAX source proposal v1\nsource_context="));
    // `alpha` is exact task bytes, hex encoded by `context_bytes`; the source
    // context also carries the checked state/observation fields and grammar.
    assert!(prompt.contains("\"task_objective\":\"616c706861\""));
    assert!(prompt.contains("\"observation\":"));
    assert!(prompt.contains("canonical_agent_proposal_schema="));
    let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    assert_eq!(receipt["status"], "complete");
    assert_eq!(receipt["money"]["reserved_minor"], 7);
}

#[test]
fn priced_adapter_malformed_response_retries_with_two_durable_quotes() {
    let fixture = Fixture::new();
    let manifest = source_project(
        &fixture.0.join("project"),
        source_fixture::SOURCE,
        "fixture.agent.type.state",
    );
    let config = source_config(&fixture, &manifest);
    price_config(&config, serde_json::json!(7), serde_json::json!(14), "USD");
    let checkpoint = fixture.0.join("checkpoint");
    let calls = Rc::new(Cell::new(0));
    let prompts = Rc::new(RefCell::new(Vec::new()));
    let answers = vec!["not-json\n".to_owned(), recorded_answer(&manifest)];
    let receipt = super::super::run::execute_with_runner(
        run_command("run", &config, &checkpoint, &fixture.0.join("scratch")),
        SequencedRecordedRunner {
            answers: answers.clone(),
            next: 0,
            last_answer: None,
            prompts: prompts.clone(),
            calls: calls.clone(),
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 2);
    assert_eq!(prompts.borrow().len(), 2);
    let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    assert_eq!(receipt["status"], "complete");
    assert_eq!(receipt["model_dispatches"], 2);
    assert_eq!(receipt["effect_dispatches"], 1);
    assert_eq!(receipt["money"]["reserved_minor"], 14);
    assert_eq!(receipt["money"]["unknown_charge_reservation_minor"], 14);
    let journal: serde_json::Value =
        serde_json::from_slice(&fs::read(checkpoint.join("checkpoint.json")).unwrap()).unwrap();
    let rows = journal["entries"].as_array().unwrap();
    let intents: Vec<_> = rows
        .iter()
        .filter(|row| row["kind"] == "priced_attempt_intent")
        .collect();
    let responses: Vec<_> = rows
        .iter()
        .filter(|row| row["kind"] == "attempt_settled")
        .collect();
    assert_eq!(intents.len(), 2);
    assert_eq!(responses.len(), 2);
    assert_eq!(
        rows.iter()
            .filter(|row| row["kind"] == "priced_attempt_usage")
            .count(),
        2
    );
    for (index, ((intent, response), prompt)) in intents
        .iter()
        .zip(&responses)
        .zip(prompts.borrow().iter())
        .enumerate()
    {
        assert_eq!(intent["request_bytes"], prompt.len());
        assert_eq!(intent["reserved_units"], 1);
        assert_eq!(intent["reserved_minor"], 7);
        assert_eq!(intent["money_ordinal"], index);
        let expected_hex: String = answers[index]
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            response["response"], expected_hex,
            "even malformed response work remains durable"
        );
    }
    let before = fs::read(checkpoint.join("checkpoint.json")).unwrap();
    let resumed = super::super::run::execute_with_runner(
        run_command(
            "resume",
            &config,
            &checkpoint,
            &fixture.0.join("resume-scratch"),
        ),
        runner(recorded_answer(&manifest), &calls),
    )
    .unwrap();
    let resumed: serde_json::Value = serde_json::from_str(&resumed).unwrap();
    assert_eq!(resumed["money"], receipt["money"]);
    assert_eq!(calls.get(), 2);
    assert_eq!(
        fs::read(checkpoint.join("checkpoint.json")).unwrap(),
        before
    );
}

#[test]
fn invalid_or_overflow_priced_quote_refuses_before_store_or_transport() {
    for (price, ceiling, currency, reservation_units) in [
        (serde_json::json!(7), serde_json::json!(7), "usd", 1),
        (serde_json::json!(-1), serde_json::json!(7), "USD", 1),
        (serde_json::json!(7), serde_json::json!(-1), "USD", 1),
        (
            serde_json::json!(i64::MAX),
            serde_json::json!(i64::MAX),
            "USD",
            2,
        ),
    ] {
        let fixture = Fixture::new();
        let manifest = source_project(
            &fixture.0.join("project"),
            source_fixture::SOURCE,
            "fixture.agent.type.state",
        );
        let config = source_config(&fixture, &manifest);
        price_config(&config, price, ceiling, currency);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        value["reservation_units"] = serde_json::json!(reservation_units);
        fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
        let checkpoint = fixture.0.join("checkpoint");
        let calls = Rc::new(Cell::new(0));
        assert!(super::super::run::execute_with_runner(
            run_command("run", &config, &checkpoint, &fixture.0.join("scratch")),
            runner(recorded_answer(&manifest), &calls),
        )
        .is_err());
        assert_eq!(calls.get(), 0);
        assert!(!checkpoint.join("checkpoint.json").exists());
    }
}
