use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use semaprax::agent_lifecycle::iterative::source_live::SourceIoLimits;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn config(schema: &str) -> Value {
    serde_json::json!({
        "schema": schema,
        "manifest": "/physical/project/semaprax.toml",
        "source_path": "src/app.spx",
        "agent_id": "fixture.agent",
        "step_id": "fixture.agent.type.step",
        "task_path": "/physical/task.txt",
        "task_budget": 1,
        "read_path": "/physical/read.txt",
        "deadline_millis": 2_000_000_000_000i64,
        "ceiling": 3,
        "reservation_units": 1,
        "max_iterations": 2,
        "max_stages": 16,
        "max_steps_per_stage": 100,
        "max_total_steps": 5000,
        "response_limit": 4096,
    })
}

fn load(value: &Value) -> Result<SessionConfig, CliError> {
    let path = std::env::temp_dir().join(format!(
        "spx-source-live-options-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    let result = SessionConfig::load(&path);
    let _ = fs::remove_file(path);
    result
}

#[test]
fn v1_stays_unpriced_and_v2_requires_an_exact_integer_quote() {
    assert_eq!(
        load(&config("semaprax.source-live-cli.config.v1"))
            .unwrap()
            .pricing,
        None
    );

    let mut v2 = config("semaprax.source-live-cli.config.v2");
    v2["pricing"] = serde_json::json!({
        "currency": "USD",
        "minor_unit_exponent": 2,
        "price_per_work_unit_minor": 7,
        "money_ceiling_minor": 70,
    });
    assert_eq!(
        load(&v2).unwrap().pricing,
        Some(SourceLivePricing {
            currency: "USD".into(),
            minor_unit_exponent: 2,
            price_per_work_unit_minor: 7,
            money_ceiling_minor: 70,
        })
    );
}

#[test]
fn v2_refuses_absent_or_malformed_pricing_without_downgrade() {
    let missing = config("semaprax.source-live-cli.config.v2");
    assert!(load(&missing).is_err());

    let mut malformed = config("semaprax.source-live-cli.config.v2");
    malformed["pricing"] = serde_json::json!({
        "currency": "usd",
        "minor_unit_exponent": 10,
        "price_per_work_unit_minor": 0,
        "money_ceiling_minor": -1,
    });
    assert!(load(&malformed).is_err());

    let mut unknown = config("semaprax.source-live-cli.config.v2");
    unknown["pricing"] = serde_json::json!({
        "currency": "USD",
        "minor_unit_exponent": 2,
        "price_per_work_unit_minor": 7,
        "money_ceiling_minor": 70,
        "provider_cost": 1.5,
    });
    assert!(load(&unknown).is_err());
}

#[test]
fn v3_requires_an_exact_priced_io_policy_without_widening_v2() {
    let mut v3 = config("semaprax.source-live-cli.config.v3");
    v3["pricing"] = serde_json::json!({
        "currency": "USD", "minor_unit_exponent": 6,
        "price_per_work_unit_minor": 7, "money_ceiling_minor": 70,
    });
    v3["io_limits"] = serde_json::json!({
        "max_request_bytes": 0,
        "max_total_request_bytes": 0,
        "max_total_response_bytes": 0,
    });
    assert_eq!(
        load(&v3).unwrap().io_limits,
        Some(SourceIoLimits {
            max_request_bytes: 0,
            max_total_request_bytes: 0,
            max_total_response_bytes: 0,
        })
    );

    let mut missing = v3.clone();
    missing.as_object_mut().unwrap().remove("io_limits");
    assert!(load(&missing).is_err());
    let mut unknown = v3.clone();
    unknown["io_limits"]["provider_bytes"] = serde_json::json!(1);
    assert!(load(&unknown).is_err());
    let mut oversized = v3;
    oversized["io_limits"]["max_request_bytes"] = serde_json::json!(65_537);
    assert!(load(&oversized).is_err());
}
