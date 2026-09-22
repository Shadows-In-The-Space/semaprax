//! Unit coverage for the shared document helpers every live-smoke value uses.
//!
//! The end-to-end contract -- target binding, plan derivation, operator grant,
//! preflight and record -- needs a retained Project and a bound source model,
//! so it lives in the owning integration harness at
//! `tests/agent_runtime_v1/live_repair_smoke_v1.rs`. What is checked here is the
//! wire discipline those values all depend on.

use serde_json::json;

use super::*;

const DOMAIN: &[u8] = b"semaprax.live-repair-smoke.test.v1\0";

#[test]
fn canonical_rendering_ends_in_one_newline_and_is_stable() {
    let value = json!({"b": 2, "a": 1});
    let first = render(&value).expect("a small object renders");
    let second = render(&value).expect("a small object renders twice");
    assert_eq!(first, second, "rendering is deterministic");
    assert!(first.ends_with('\n'));
    assert_eq!(
        first.matches('\n').count(),
        1,
        "exactly one trailing newline, never an embedded one"
    );
}

#[test]
fn rendering_refuses_a_document_past_the_shared_transport_bound() {
    let oversized = json!({"payload": "x".repeat(MAX_LIVE_REPAIR_SMOKE_BYTES)});
    assert!(render(&oversized).is_err());
}

#[test]
fn replaying_requires_the_exact_schema_bytes_and_digest() {
    let value = json!({"field": "value", "schema": "semaprax.live-repair-smoke-plan.v1"});
    let bytes = render(&value).expect("the document renders");
    let expected = digest(DOMAIN, bytes.as_bytes());

    replay_document(
        DOMAIN,
        LIVE_REPAIR_SMOKE_PLAN_SCHEMA,
        &expected,
        bytes.as_bytes(),
    )
    .expect("its own bytes replay");

    assert!(
        replay_document(
            DOMAIN,
            LIVE_REPAIR_SMOKE_RECORD_SCHEMA,
            &expected,
            bytes.as_bytes()
        )
        .is_err(),
        "a document must not be read under a different schema"
    );

    let tampered = bytes.replace("value", "other");
    assert!(
        replay_document(
            DOMAIN,
            LIVE_REPAIR_SMOKE_PLAN_SCHEMA,
            &expected,
            tampered.as_bytes()
        )
        .is_err(),
        "tampered bytes fail the digest check"
    );

    let noncanonical = format!("{{ \"schema\": \"{LIVE_REPAIR_SMOKE_PLAN_SCHEMA}\" }}\n");
    let noncanonical_digest = digest(DOMAIN, noncanonical.as_bytes());
    assert!(
        replay_document(
            DOMAIN,
            LIVE_REPAIR_SMOKE_PLAN_SCHEMA,
            &noncanonical_digest,
            noncanonical.as_bytes()
        )
        .is_err(),
        "a digest over noncanonical bytes is still refused"
    );

    assert!(replay_document(DOMAIN, LIVE_REPAIR_SMOKE_PLAN_SCHEMA, &expected, b"").is_err());
}

#[test]
fn digests_are_canonical_prefixed_lowercase_sha256_labels() {
    let produced = digest(DOMAIN, b"payload");
    assert!(produced.starts_with("sha256:"));
    assert_eq!(produced.len(), 71);
    validate_digest_label(&produced).expect("this contract's own digests validate");

    for rejected in [
        "",
        "sha256:",
        &"0".repeat(64),
        &format!("sha256:{}", "0".repeat(63)),
        &format!("SHA256:{}", "0".repeat(64)),
        &format!("sha256:{}", "A".repeat(64)),
        &format!("sha256:{}", "g".repeat(64)),
    ] {
        assert!(
            validate_digest_label(rejected).is_err(),
            "{rejected} is not a canonical digest label"
        );
    }
}

#[test]
fn labels_are_bounded_trimmed_and_free_of_control_characters() {
    validate_label("fixture.repair.value", "detail").expect("an ordinary identity is admitted");
    for rejected in [
        "",
        " leading",
        "trailing ",
        "with\nnewline",
        "with\ttab",
        &"x".repeat(MAX_LABEL_BYTES + 1),
    ] {
        assert!(validate_label(rejected, "detail").is_err());
    }
    validate_label(&"x".repeat(MAX_LABEL_BYTES), "detail").expect("the bound itself is admitted");
}

#[test]
fn the_smoke_turn_range_demands_a_second_turn_and_stays_bounded() {
    assert!(
        MIN_SMOKE_TURNS >= 2,
        "a live smoke that cannot reach a second turn cannot exercise feedback"
    );
    assert!(MAX_SMOKE_TURNS >= MIN_SMOKE_TURNS);
    assert!(
        MAX_SMOKE_TURNS <= 64,
        "a smoke stays a smoke rather than becoming an unbounded paid soak"
    );
}

#[test]
fn refusals_carry_the_stable_bounded_diagnostic_code() {
    let diagnostics = refused("detail");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].code, "SPX-G583");
    assert!(diagnostics[0].message.contains("live repair smoke refused"));
    assert!(diagnostics[0].message.contains("detail"));
}
