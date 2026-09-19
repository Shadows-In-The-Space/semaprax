//! Cases for the registry wire formats. Every refusal asserts the exact
//! diagnostic code, and the two properties that matter -- that the decoder
//! round-trips every field, and that it decides *nothing* about registry
//! rules -- get their own tests rather than being argued only in prose.

use super::super::tests::{calculator_entry, meaning_entry, yanked};
use super::super::{build_snapshot, PublicationStatus};
use super::*;

fn with_provenance(entry: PublishedEntry, digest: &str) -> PublishedEntry {
    PublishedEntry {
        provenance_digest: Some(digest.to_owned()),
        ..entry
    }
}

const TEMPLATE: &str = r#"{
    "schema": "semaprax.registry-resolution-template.v1",
    "requirements": [{"package": "examples.meaning", "range": "^1.0.0"}],
    "target": "native64",
    "allowed_capabilities": [],
    "yank_policy": "exclude_yanked",
    "max_bytes": 65536
}"#;

// --- Round trip --------------------------------------------------------------

#[test]
fn render_then_parse_round_trips_every_field() {
    let entries = vec![
        meaning_entry("1.0.0", "alpha"),
        with_provenance(calculator_entry("2.0.0", "beta"), "sha256:abc"),
        yanked(
            meaning_entry("1.1.0", "gamma"),
            "unsound \"quoted\" reason\nwith newline",
        ),
    ];
    let rendered = render_registry_document(&entries);
    let decoded = parse_registry_document(&rendered).expect("round trip");
    assert_eq!(decoded, entries);
}

#[test]
fn a_single_entry_document_uses_the_same_shape_as_one_array_element() {
    let entry = yanked(meaning_entry("1.0.0", "alpha"), "withdrawn");
    let decoded = parse_entry_document(&render_entry(&entry)).expect("entry round trip");
    assert_eq!(decoded, entry);
    assert!(matches!(decoded.status, PublicationStatus::Yanked { .. }));
}

// --- The decoder decides no registry rule -----------------------------------

/// The load-bearing separation: a document may decode cleanly and still be
/// refused by the registry. `std.*` is the reserved namespace `SPX-PKR602`
/// owns, and this proves the decoder does not shadow it with a `613`.
#[test]
fn a_reserved_namespace_entry_decodes_and_is_refused_only_by_build_snapshot() {
    let entry = PublishedEntry {
        package: "std.core".to_owned(),
        ..meaning_entry("1.0.0", "alpha")
    };
    let decoded =
        parse_registry_document(&render_registry_document(&[entry])).expect("decode succeeds");
    assert_eq!(decoded[0].package, "std.core");
    let error = build_snapshot(&decoded).expect_err("registry refuses it");
    assert_eq!(error.code, "SPX-PKR602");
}

/// The passing control for the test above: the same document with an
/// admitted name builds, so that refusal is about the namespace and not
/// about the document having come through the decoder at all.
#[test]
fn an_admitted_decoded_document_builds_a_snapshot() {
    let decoded = parse_registry_document(&render_registry_document(&[meaning_entry(
        "1.0.0", "alpha",
    )]))
    .expect("decode");
    assert!(build_snapshot(&decoded).is_ok());
}

// --- Hostile and malformed documents ----------------------------------------

fn refused(document: &str) -> Diagnostic {
    parse_registry_document(document).expect_err("must be refused")
}

#[test]
fn a_document_that_is_not_json_is_refused() {
    assert_eq!(refused("not json at all").code, "SPX-PKR613");
}

#[test]
fn a_document_that_is_not_an_object_is_refused() {
    assert_eq!(refused("[]").code, "SPX-PKR613");
}

#[test]
fn a_document_declaring_another_schema_is_refused() {
    let document = render_registry_document(&[]).replace(DOCUMENT_SCHEMA, "semaprax.something.v1");
    assert_eq!(refused(&document).code, "SPX-PKR613");
}

#[test]
fn an_unknown_top_level_field_is_refused_rather_than_ignored() {
    let document = format!(
        "{{\"schema\":\"{DOCUMENT_SCHEMA}\",\"entries\":[],\"registry_url\":\"https://x\"}}"
    );
    assert_eq!(refused(&document).code, "SPX-PKR613");
}

#[test]
fn an_unknown_entry_field_is_refused_rather_than_ignored() {
    let entry = render_entry(&meaning_entry("1.0.0", "alpha"));
    let tampered = entry.replace("\"license\":", "\"trusted\":true,\"license\":");
    let document = format!("{{\"schema\":\"{DOCUMENT_SCHEMA}\",\"entries\":[{tampered}]}}");
    assert_eq!(refused(&document).code, "SPX-PKR613");
}

#[test]
fn a_missing_entry_field_is_refused() {
    let entry = render_entry(&meaning_entry("1.0.0", "alpha"));
    let tampered = entry.replace("\"license\":\"Apache-2.0\",", "");
    let document = format!("{{\"schema\":\"{DOCUMENT_SCHEMA}\",\"entries\":[{tampered}]}}");
    assert_eq!(refused(&document).code, "SPX-PKR613");
}

#[test]
fn an_unknown_publication_state_is_refused() {
    let entry = render_entry(&meaning_entry("1.0.0", "alpha"));
    let tampered = entry.replace("{\"state\":\"active\"}", "{\"state\":\"revoked\"}");
    let document = format!("{{\"schema\":\"{DOCUMENT_SCHEMA}\",\"entries\":[{tampered}]}}");
    assert_eq!(refused(&document).code, "SPX-PKR613");
}

#[test]
fn a_yank_without_a_reason_is_refused() {
    let entry = render_entry(&meaning_entry("1.0.0", "alpha"));
    let tampered = entry.replace("{\"state\":\"active\"}", "{\"state\":\"yanked\"}");
    let document = format!("{{\"schema\":\"{DOCUMENT_SCHEMA}\",\"entries\":[{tampered}]}}");
    assert_eq!(refused(&document).code, "SPX-PKR613");
}

#[test]
fn a_non_string_field_is_refused_rather_than_coerced() {
    let entry = render_entry(&meaning_entry("1.0.0", "alpha"));
    let tampered = entry.replace("\"license\":\"Apache-2.0\"", "\"license\":7");
    let document = format!("{{\"schema\":\"{DOCUMENT_SCHEMA}\",\"entries\":[{tampered}]}}");
    assert_eq!(refused(&document).code, "SPX-PKR613");
}

#[test]
fn more_entries_than_the_registry_admits_are_refused_before_any_entry_is_parsed() {
    let entries = vec!["{}"; MAX_ENTRIES + 1].join(",");
    let document = format!("{{\"schema\":\"{DOCUMENT_SCHEMA}\",\"entries\":[{entries}]}}");
    let error = refused(&document);
    assert_eq!(error.code, "SPX-PKR613");
    assert!(error.message.contains("over the"), "{}", error.message);
}

// --- Resolution templates ----------------------------------------------------

#[test]
fn a_valid_template_decodes_into_the_binding_layers_own_types() {
    let decoded = parse_template_document(TEMPLATE).expect("template");
    assert_eq!(decoded.template.requirements.len(), 1);
    assert_eq!(decoded.template.requirements[0].range, "^1.0.0");
    assert_eq!(decoded.template.target, "native64");
    assert_eq!(decoded.policy, YankPolicy::ExcludeYanked);
}

#[test]
fn every_yank_policy_spelling_the_binding_layer_renders_is_accepted() {
    for (text, expected) in [
        ("exclude_yanked", YankPolicy::ExcludeYanked),
        ("refuse_if_yanked", YankPolicy::RefuseIfYanked),
        (
            "allow_yanked_with_warning",
            YankPolicy::AllowYankedWithWarning,
        ),
    ] {
        assert_eq!(parse_yank_policy(text).expect("policy"), expected);
    }
}

#[test]
fn an_unknown_yank_policy_is_refused_rather_than_defaulted() {
    let document = TEMPLATE.replace("exclude_yanked", "ignore_yanks");
    let error = parse_template_document(&document).expect_err("refused");
    assert_eq!(error.code, "SPX-PKR613");
}

#[test]
fn a_template_with_an_unknown_field_is_refused() {
    let document = TEMPLATE.replace("\"target\":", "\"registry\": \"https://x\", \"target\":");
    assert_eq!(
        parse_template_document(&document)
            .expect_err("refused")
            .code,
        "SPX-PKR613"
    );
}

#[test]
fn more_requirements_than_the_resolver_admits_are_refused() {
    let one = "{\"package\": \"examples.meaning\", \"range\": \"^1.0.0\"}";
    let many = vec![one; MAX_REQUIREMENTS + 1].join(",");
    let document = TEMPLATE.replace(one, &many);
    assert_eq!(
        parse_template_document(&document)
            .expect_err("refused")
            .code,
        "SPX-PKR613"
    );
}

/// `max_bytes` is validated by the resolver's own `ResolutionOptions::new`,
/// so an out-of-range value keeps *that* module's code rather than this
/// decoder's -- the same deference every other rule here shows.
#[test]
fn an_out_of_range_max_bytes_keeps_the_resolver_options_own_code() {
    let document = TEMPLATE.replace("65536", "1");
    let error = parse_template_document(&document).expect_err("refused");
    assert_ne!(error.code, "SPX-PKR613");
}
