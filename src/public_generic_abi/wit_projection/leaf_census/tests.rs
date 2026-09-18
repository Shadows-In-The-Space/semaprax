//! Executable evidence for the owned-leaf census agreement gate.
//!
//! The positive case is a real program compiled through `crate::parse` +
//! `crate::hir::resolve` and classified through the actual
//! [`crate::public_generic_abi::classifier::classify`] admission — the same
//! fixture [`super::super::tests`] already uses, reused rather than
//! re-declared so the two modules cannot drift into describing different
//! programs.
//!
//! Every negative case mutates the *structured* projection and re-runs
//! [`check_owned_leaf_census`] against the unchanged classifier facts, so
//! each asserts that the gate catches a specific corruption with a specific
//! code — never merely that a well-formed projection passes.

use sha2::{Digest, Sha256};

use super::*;
use crate::public_generic_abi::classifier::classify;
use crate::public_generic_abi::wit_projection::{
    project_admitted_subject, WitFieldV1, OWNED_BYTES_RESOURCE, WIT_INTERFACE, WIT_PACKAGE,
    WIT_WORLD,
};

use super::super::tests::{resolved, BASE};

/// The one owned leaf `Pair<Leaf, i64>` has, in the grammar's own
/// `@<len>:<id>` path framing: `Pair.left` then `Leaf.head`.
const EXPECTED_LEAF: &str = "@24:wit_projection.pair.left/@24:wit_projection.leaf.head";

fn projected() -> (AdmittedSubject, WitTypeProjectionV1) {
    let program = resolved(BASE);
    let admitted = classify(&program, "wit_projection.take").expect("fixture must classify");
    let projection = project_admitted_subject(&admitted).expect("fixture must project");
    (admitted, projection)
}

fn hex_digest(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn owned_bytes_field_type_literal_matches_the_rendered_resource_handle() {
    assert_eq!(
        OWNED_BYTES_FIELD_TYPE,
        format!("own<{OWNED_BYTES_RESOURCE}>"),
        "the census recognises leaves by this exact spelling; a renderer change must be made here \
         too"
    );
}

#[test]
fn census_recomputes_the_descriptor_inventory_from_the_projected_structure() {
    let (admitted, projection) = projected();

    // Not vacuous: both sides being empty would make the equality below
    // trivially true, so pin the expected inventory itself first.
    assert_eq!(
        admitted.input().owned_leaves,
        vec![EXPECTED_LEAF.to_owned()]
    );
    assert_eq!(
        admitted.result().owned_leaves,
        vec![EXPECTED_LEAF.to_owned()]
    );

    let from_projection = projected_owned_leaves(&projection, &projection.input_type).unwrap();
    assert_eq!(from_projection, admitted.input().owned_leaves);
    // The gate itself already ran inside `project_admitted_subject`; running
    // it again here names it explicitly as the thing under test.
    check_owned_leaf_census(&admitted, &projection).unwrap();
}

#[test]
fn a_dropped_owned_leaf_field_is_refused_rather_than_rendered() {
    let (admitted, mut projection) = projected();
    let leaf = projection
        .records
        .iter_mut()
        .find(|record| {
            record
                .fields
                .iter()
                .any(|field| field.type_text == OWNED_BYTES_FIELD_TYPE)
        })
        .expect("the fixture has one owned-bytes record");
    leaf.fields
        .retain(|field| field.type_text != OWNED_BYTES_FIELD_TYPE);

    let error = check_owned_leaf_census(&admitted, &projection).unwrap_err();
    assert_eq!(error.code, LEAF_CENSUS_DISAGREEMENT);
    assert!(
        error
            .message
            .contains("descriptor has 1 owned leaves, projection has 0"),
        "{}",
        error.message
    );
}

#[test]
fn a_leaf_reached_under_a_different_field_identity_is_refused() {
    let (admitted, mut projection) = projected();
    for record in &mut projection.records {
        for field in &mut record.fields {
            if field.type_text == OWNED_BYTES_FIELD_TYPE {
                field.source_field_id = "wit_projection.leaf.tail".to_owned();
            }
        }
    }

    let error = check_owned_leaf_census(&admitted, &projection).unwrap_err();
    assert_eq!(error.code, LEAF_CENSUS_DISAGREEMENT);
    assert!(error.message.contains("leaf 0 is"), "{}", error.message);
    assert!(
        error.message.contains("wit_projection.leaf.tail"),
        "{}",
        error.message
    );
}

#[test]
fn a_field_naming_a_record_the_projection_never_declared_is_refused() {
    let (admitted, mut projection) = projected();
    let root = projection.input_type.clone();
    let record = projection
        .records
        .iter_mut()
        .find(|record| record.name == root)
        .expect("the input record is declared");
    record.fields[0].type_text = "spx-deadbeef".to_owned();

    let error = check_owned_leaf_census(&admitted, &projection).unwrap_err();
    assert_eq!(error.code, UNDECLARED_RECORD);
    assert!(error.message.contains("spx-deadbeef"), "{}", error.message);
}

#[test]
fn more_owned_leaves_than_the_boundary_profile_admits_is_refused_not_truncated() {
    let fields = (0..=MAX_OWNED_LEAVES_PER_INSTANCE)
        .map(|index| WitFieldV1 {
            source_field_id: format!("fixture.field{index}"),
            name: format!("spx-{index:04}"),
            type_text: OWNED_BYTES_FIELD_TYPE.to_owned(),
        })
        .collect::<Vec<_>>();
    let projection = WitTypeProjectionV1 {
        schema: WIT_TYPE_PROJECTION_SCHEMA,
        package: WIT_PACKAGE,
        interface: WIT_INTERFACE,
        world: WIT_WORLD,
        uses_owned_bytes_resource: true,
        records: vec![WitRecordV1 {
            source_term: "@7:fixture<>".to_owned(),
            name: "spx-root".to_owned(),
            fields,
        }],
        input_type: "spx-root".to_owned(),
        result_type: "spx-root".to_owned(),
        wit: String::new(),
    };

    let error = projected_owned_leaves(&projection, "spx-root").unwrap_err();
    assert_eq!(error.code, CENSUS_CAPACITY);
    assert!(
        error.message.contains("transitive owned leaf bound"),
        "{}",
        error.message
    );
}

/// A byte golden. The parent module's
/// `projection_is_byte_deterministic_across_repeated_calls`
/// only proves two calls in one process agree; this pins the exact rendered
/// bytes, so a refactor that changed layout, ordering, or identifier
/// encoding could not stay silent.
#[test]
fn rendered_wit_bytes_are_pinned_to_a_golden_digest() {
    let (_, projection) = projected();
    assert_eq!(projection.wit.len(), 634, "{}", projection.wit);
    assert_eq!(
        hex_digest(&projection.wit),
        "7f9999b31c3f7dc4bcbccf40516d33c44ac0c4aedf5945060ff6ef5ff909dc0f",
        "{}",
        projection.wit
    );
}
