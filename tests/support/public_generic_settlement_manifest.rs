//! One bounded, digest-pinned fixture table shared by the library and native
//! settlement harnesses. This is test data, not a public descriptor verifier.

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

const MANIFEST: &str = include_str!("../fixtures/public-generic-settlement-v1/cases.json");
pub const DESCRIPTOR_FIXTURE: &[u8] =
    include_bytes!("../fixtures/public-generic-settlement-v1/descriptor.txt");

const SCHEMA: &str = "semaprax.public-generic-settlement-corpus.v1";
const MAX_PAYLOAD: usize = 16 * 1024 * 1024 + 1;
const LABELS: [&str; 14] = [
    "FrameValidated",
    "LeafAllocationStarted",
    "LeafAllocationCommitted",
    "LeafPayloadCopied",
    "InputValuePrepared",
    "InputTransferCommitted",
    "ExecutionStarted",
    "ExecutionFinished",
    "ResultLeafAllocationStarted",
    "ResultLeafAllocationCommitted",
    "ResultValuePrepared",
    "ResultCommit",
    "LeafRelease",
    "CarrierRelease",
];

#[derive(Debug)]
pub struct FixtureCase {
    pub case_id: String,
    pub input_leaves: Vec<Vec<u8>>,
    pub injection: Option<usize>,
    pub cleanup_injection: Option<usize>,
    pub accepted: bool,
    pub status: i32,
}

fn closed_keys(value: &Value, keys: &[&str]) {
    let actual: BTreeSet<_> = value
        .as_object()
        .expect("expected object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        actual,
        keys.iter().copied().collect::<BTreeSet<_>>(),
        "closed manifest keys"
    );
}

fn number(value: &Value, max: usize) -> usize {
    let n = value.as_u64().expect("expected nonnegative integer");
    assert!(n <= max as u64, "manifest bound exceeded");
    n as usize
}

fn injection(value: &Value) -> Option<usize> {
    if value.is_null() {
        None
    } else {
        Some(
            LABELS
                .iter()
                .position(|label| Some(*label) == value.as_str())
                .expect("unknown injection label"),
        )
    }
}

fn digest(direction: &str, bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(format!("{SCHEMA}/{direction}\0").as_bytes());
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    format!(
        "sha256:{:x}",
        semaprax::digest_hex::LowerHex(hash.finalize())
    )
}

/// Parse only canonical JSON. Re-render equality also rejects duplicate keys,
/// reordered keys, alternate numeric encodings and trailing documents.
fn parse(text: &str) -> Vec<FixtureCase> {
    assert!(text.len() <= 64 * 1024, "manifest byte bound exceeded");
    let value: Value = serde_json::from_str(text).expect("invalid manifest JSON");
    assert_eq!(
        format!("{}\n", serde_json::to_string(&value).unwrap()),
        text,
        "noncanonical manifest"
    );
    closed_keys(
        &value,
        &[
            "schema",
            "profile",
            "carrier_format",
            "normalized_result_format",
            "applicable_engines",
            "cases",
        ],
    );
    assert_eq!(value["schema"], SCHEMA);
    assert_eq!(value["profile"], "flat-owned-bytes-reference-fixture.v1");
    assert_eq!(
        value["carrier_format"],
        "u64le-leaf-count-and-u64le-length-framed-bytes"
    );
    assert_eq!(
        value["normalized_result_format"],
        "u64le-length-framed-bytes-without-leaf-count"
    );
    assert_eq!(
        value["applicable_engines"],
        serde_json::json!([
            "interpreter",
            "core-wasm-model",
            "native-c11-O0",
            "native-c11-O2"
        ])
    );
    let cases = value["cases"].as_array().expect("expected cases");
    assert!(!cases.is_empty() && cases.len() <= 64, "case count bound");
    let mut ids = BTreeSet::new();
    cases
        .iter()
        .map(|case| {
            closed_keys(
                case,
                &[
                    "case_id",
                    "description",
                    "input_leaves",
                    "failure_injection_id",
                    "compound_cleanup_injection",
                    "expected_accepted",
                    "expected_primary_status",
                    "expected_endpoint_invoked",
                    "input_carrier_digest",
                    "expected_result_carrier_digest",
                    "expected_final_live_allocations",
                    "expected_final_live_handles",
                    "expected_final_live_bytes",
                ],
            );
            let id = case["case_id"].as_str().expect("expected case ID");
            assert!(
                !id.is_empty()
                    && id.len() <= 100
                    && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
                "invalid case ID"
            );
            assert!(ids.insert(id), "duplicate case ID");
            assert!(case["description"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 512));
            let mut leaves = Vec::new();
            let mut total = 0usize;
            let recipes = case["input_leaves"].as_array().expect("expected recipes");
            assert!(recipes.len() <= 257, "recipe count bound");
            for recipe in recipes {
                let (leaf, count) = if recipe.get("hex").is_some() {
                    closed_keys(recipe, &["hex"]);
                    let text = recipe["hex"].as_str().expect("expected hex");
                    assert!(
                        text.len() <= 2 * 65537
                            && text.len() % 2 == 0
                            && text
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                        "noncanonical payload hex"
                    );
                    (
                        (0..text.len())
                            .step_by(2)
                            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                            .collect::<Vec<_>>(),
                        1,
                    )
                } else {
                    closed_keys(recipe, &["byte", "length", "count"]);
                    let length = number(&recipe["length"], 65537);
                    let count = number(&recipe["count"], 257);
                    assert!(count > 0, "empty repeat recipe");
                    (vec![number(&recipe["byte"], 255) as u8; length], count)
                };
                assert!(leaves.len() + count <= 257, "leaf count bound");
                total = total
                    .checked_add(leaf.len().checked_mul(count).unwrap())
                    .unwrap();
                assert!(total <= MAX_PAYLOAD, "fixture payload bound exceeded");
                leaves.extend(std::iter::repeat_n(leaf, count));
            }
            let mut input = (leaves.len() as u64).to_le_bytes().to_vec();
            let mut result = Vec::new();
            for leaf in &leaves {
                input.extend_from_slice(&(leaf.len() as u64).to_le_bytes());
                input.extend_from_slice(leaf);
                result.extend_from_slice(&(leaf.len() as u64).to_le_bytes());
                result.extend(leaf.iter().rev().copied());
            }
            assert_eq!(
                case["input_carrier_digest"],
                digest("input", &input),
                "input digest"
            );
            let accepted = case["expected_accepted"]
                .as_bool()
                .expect("expected boolean");
            let status = number(&case["expected_primary_status"], 13) as i32;
            assert_eq!(accepted, status == 0, "inconsistent accepted/status");
            let expected_result = if accepted {
                Value::String(digest("result", &result))
            } else {
                Value::Null
            };
            assert_eq!(
                case["expected_result_carrier_digest"], expected_result,
                "result digest"
            );
            let injected = injection(&case["failure_injection_id"]);
            let cleanup = injection(&case["compound_cleanup_injection"]);
            assert!(
                cleanup.is_none_or(|label| label >= 12),
                "not a cleanup event"
            );
            assert!(
                cleanup.is_none() || injected.is_some(),
                "cleanup needs primary injection"
            );
            let within_bounds =
                leaves.len() <= 256 && leaves.iter().all(|leaf| leaf.len() <= 65536);
            let invoked = within_bounds && injected.is_none_or(|label| label >= 7);
            assert_eq!(
                case["expected_endpoint_invoked"], invoked,
                "endpoint expectation"
            );
            for field in [
                "expected_final_live_allocations",
                "expected_final_live_handles",
                "expected_final_live_bytes",
            ] {
                assert_eq!(case[field].as_u64(), Some(0), "nonzero terminal resources");
            }
            FixtureCase {
                case_id: id.to_owned(),
                input_leaves: leaves,
                injection: injected,
                cleanup_injection: cleanup,
                accepted,
                status,
            }
        })
        .collect()
}

pub fn cases() -> Vec<FixtureCase> {
    parse(MANIFEST)
}

#[test]
fn settlement_manifest_is_canonical_bounded_and_digest_pinned() {
    assert_eq!(cases().len(), 22);
}

#[test]
fn settlement_manifest_rejects_tampering_and_noncanonical_bytes() {
    let original: Value = serde_json::from_str(MANIFEST).unwrap();
    for field in [
        "case_id",
        "input_carrier_digest",
        "expected_result_carrier_digest",
        "failure_injection_id",
        "expected_primary_status",
        "expected_endpoint_invoked",
    ] {
        let mut changed = original.clone();
        changed["cases"][0][field] = Value::String("invalid value".to_owned());
        let text = format!("{}\n", serde_json::to_string(&changed).unwrap());
        assert!(
            std::panic::catch_unwind(|| parse(&text)).is_err(),
            "accepted mutation: {field}"
        );
    }
    for text in [
        MANIFEST.trim_end().to_owned(),
        format!(" {MANIFEST}"),
        MANIFEST.replacen("{", "{\"unknown\":0,", 1),
        MANIFEST.replacen("{", "{\"schema\":\"duplicate\",", 1),
    ] {
        assert!(std::panic::catch_unwind(|| parse(&text)).is_err());
    }
}
