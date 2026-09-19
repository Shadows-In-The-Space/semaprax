//! Executable evidence for [`compare`] and [`require_compatible`].
//!
//! Every positive case is two real programs compiled through `crate::parse` +
//! `crate::hir::resolve` and admitted through the actual
//! [`crate::public_generic_abi::classifier::classify`], then projected
//! through [`super::super::project_admitted_subject`] — the same technique
//! `wit_projection::tests` already uses. The delta is therefore between two
//! projections the compiler really produced, not between two hand-written
//! fixtures that could agree with the comparator while disagreeing with the
//! projector.
//!
//! Three cases are deliberately *synthetic*, built by mutating a real
//! projection struct: the added-record-declaration case, the resource
//! declaration appearing or disappearing, the schema-mismatch refusal, and
//! the report-capacity refusal all describe states no admitted signature can
//! reach from source today. (An admitted export takes its input by `own`, so
//! every admitted input owns at least one `Bytes` leaf and the world always
//! declares the resource; no record is reachable without being referenced;
//! only one projection schema exists; and no admitted signature reaches 512
//! records.) Building those by hand is the only way to prove the
//! classification and the refusals are live rather than dead code, and each
//! says so at its own site.
//!
//! Every fixture below keeps the *same line layout* as [`BASELINE`], because
//! a canonical grammar term carries a declaration coordinate (`@15:`) as well
//! as the stable id. Changing the number of lines before a declaration would
//! change its term and manufacture a delta that has nothing to do with the
//! edit under test.

use super::*;
use crate::public_generic_abi::classifier::classify;
use crate::public_generic_abi::wit_projection::{
    project_admitted_subject, tests::resolved, WitFieldV1,
};

/// The baseline program. `Leaf` carries two owned `Bytes` leaves and one
/// scalar, so a candidate can move exactly one field across the ownership
/// boundary while `Leaf` itself stays an owned record — which it must, since
/// `take` receives it by `own`.
const BASELINE: &str = r#"
module test.public_generic_wit_compat;

@id("wit_compat.leaf")
record Leaf {
    @id("wit_compat.leaf.head")
    head: Bytes,
    @id("wit_compat.leaf.tag")
    tag: i64,
    @id("wit_compat.leaf.trail")
    trail: Bytes,
}

@id("wit_compat.pair")
record Pair<T, U> {
    @id("wit_compat.pair.left")
    left: T,
    @id("wit_compat.pair.right")
    right: U,
}

@id("wit_compat.take")
fn take(value: own Pair<Leaf, i64>) -> Pair<Leaf, i64> { value }

@id("wit_compat.main")
fn main() -> i64 { 0 }
"#;

/// Every record, every field, and both generic parameters carry different
/// *display* names from [`BASELINE`]; every `@id` and every line position is
/// byte-identical. This is issue #176's "identifier-preserving display
/// rename" case.
const DISPLAY_RENAMED: &str = r#"
module test.public_generic_wit_compat;

@id("wit_compat.leaf")
record Foliage {
    @id("wit_compat.leaf.head")
    crown: Bytes,
    @id("wit_compat.leaf.tag")
    marker: i64,
    @id("wit_compat.leaf.trail")
    wake: Bytes,
}

@id("wit_compat.pair")
record Couple<A, B> {
    @id("wit_compat.pair.left")
    lhs: A,
    @id("wit_compat.pair.right")
    rhs: B,
}

@id("wit_compat.take")
fn take(value: own Couple<Foliage, i64>) -> Couple<Foliage, i64> { value }

@id("wit_compat.main")
fn main() -> i64 { 0 }
"#;

/// [`BASELINE`] with one extra scalar field in `Leaf`, replacing a blank
/// line so every later declaration keeps its coordinate.
const FIELD_ADDED: &str = r#"
module test.public_generic_wit_compat;

@id("wit_compat.leaf")
record Leaf {
    @id("wit_compat.leaf.head")
    head: Bytes,
    @id("wit_compat.leaf.tag")
    tag: i64,
    @id("wit_compat.leaf.trail")
    trail: Bytes,
    @id("wit_compat.leaf.extra")
    extra: i32,
}
@id("wit_compat.pair")
record Pair<T, U> {
    @id("wit_compat.pair.left")
    left: T,
    @id("wit_compat.pair.right")
    right: U,
}

@id("wit_compat.take")
fn take(value: own Pair<Leaf, i64>) -> Pair<Leaf, i64> { value }

@id("wit_compat.main")
fn main() -> i64 { 0 }
"#;

/// [`BASELINE`] with `Leaf`'s first two fields declared in the opposite
/// order. Same ids, same types, same count — only the canonical field
/// sequence moved.
const FIELDS_REORDERED: &str = r#"
module test.public_generic_wit_compat;

@id("wit_compat.leaf")
record Leaf {
    @id("wit_compat.leaf.tag")
    tag: i64,
    @id("wit_compat.leaf.head")
    head: Bytes,
    @id("wit_compat.leaf.trail")
    trail: Bytes,
}

@id("wit_compat.pair")
record Pair<T, U> {
    @id("wit_compat.pair.left")
    left: T,
    @id("wit_compat.pair.right")
    right: U,
}

@id("wit_compat.take")
fn take(value: own Pair<Leaf, i64>) -> Pair<Leaf, i64> { value }

@id("wit_compat.main")
fn main() -> i64 { 0 }
"#;

/// [`BASELINE`] with `Leaf::head` changed from owned `Bytes` to a scalar.
/// Cleanup responsibility for that leaf leaves the boundary; `Leaf` itself
/// still owns `trail`, so it remains an `own`-able record and the edit is a
/// pure ownership move of one field rather than a whole-record change.
const OWNERSHIP_CHANGED: &str = r#"
module test.public_generic_wit_compat;

@id("wit_compat.leaf")
record Leaf {
    @id("wit_compat.leaf.head")
    head: i64,
    @id("wit_compat.leaf.tag")
    tag: i64,
    @id("wit_compat.leaf.trail")
    trail: Bytes,
}

@id("wit_compat.pair")
record Pair<T, U> {
    @id("wit_compat.pair.left")
    left: T,
    @id("wit_compat.pair.right")
    right: U,
}

@id("wit_compat.take")
fn take(value: own Pair<Leaf, i64>) -> Pair<Leaf, i64> { value }

@id("wit_compat.main")
fn main() -> i64 { 0 }
"#;

/// [`BASELINE`] with `Leaf::tag` changed from `i64` to `f64`: a type change
/// that does *not* cross the ownership boundary.
const FIELD_RETYPED: &str = r#"
module test.public_generic_wit_compat;

@id("wit_compat.leaf")
record Leaf {
    @id("wit_compat.leaf.head")
    head: Bytes,
    @id("wit_compat.leaf.tag")
    tag: f64,
    @id("wit_compat.leaf.trail")
    trail: Bytes,
}

@id("wit_compat.pair")
record Pair<T, U> {
    @id("wit_compat.pair.left")
    left: T,
    @id("wit_compat.pair.right")
    right: U,
}

@id("wit_compat.take")
fn take(value: own Pair<Leaf, i64>) -> Pair<Leaf, i64> { value }

@id("wit_compat.main")
fn main() -> i64 { 0 }
"#;

fn projection(source: &str) -> WitTypeProjectionV1 {
    let program = resolved(source);
    let admitted = classify(&program, "wit_compat.take").unwrap();
    project_admitted_subject(&admitted).unwrap()
}

/// Locate a record by a *stable field declaration id* it contains, never by
/// its display name or by a hard-coded canonical term. A term carries a
/// declaration coordinate this test has no business hard-coding.
fn record_owning(projection: &WitTypeProjectionV1, field_id: &str) -> WitRecordV1 {
    projection
        .records
        .iter()
        .find(|record| {
            record
                .fields
                .iter()
                .any(|field| field.source_field_id == field_id)
        })
        .unwrap_or_else(|| panic!("no projected record declares `{field_id}`"))
        .clone()
}

fn kinds(report: &WitCompatibilityReportV1) -> Vec<String> {
    report.deltas.iter().map(WitDeltaV1::render).collect()
}

/// A from-scratch hex encoder, independent of `super::super::legal_name`, so
/// an expected WIT name below is never computed by the same code under test.
fn wit_name(identity: &str) -> String {
    let mut out = String::from("spx-");
    for byte in identity.as_bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------------------
// Positive controls
// ---------------------------------------------------------------------

/// The comparator must not call *everything* a delta. If this ever fails,
/// every "exactly these deltas were reported" assertion below is worthless,
/// because the comparator would be reporting differences that are not there.
#[test]
fn a_projection_compared_against_itself_reports_no_delta_and_is_compatible() {
    let baseline = projection(BASELINE);
    let report = compare(&baseline, &baseline).unwrap();
    assert!(report.deltas.is_empty(), "{:?}", report.deltas);
    assert!(report.is_compatible());
    assert_eq!(report.schema, WIT_COMPATIBILITY_SCHEMA);
    assert_eq!(report.projection_schema, baseline.schema);
    require_compatible(&baseline, &baseline).unwrap();
}

/// Issue #176's "identifier-preserving display rename" case. Every record,
/// field, and type-parameter display name differs; every `@id` is the same.
/// The projection hexes persistent identities only, so the two renderings
/// must be byte-identical and the report empty — a rename is not a delta to
/// be adjudicated, it is not a delta at all.
#[test]
fn an_identifier_preserving_display_rename_is_not_a_delta_at_all() {
    let baseline = projection(BASELINE);
    let renamed = projection(DISPLAY_RENAMED);

    // Guard against a vacuous test: the two sources really are different
    // text, really do use different display names, and no display name
    // survives into the WIT.
    assert_ne!(BASELINE, DISPLAY_RENAMED);
    assert!(BASELINE.contains("record Leaf {") && DISPLAY_RENAMED.contains("record Foliage {"));
    for leaked in ["leaf", "foliage", "crown", "couple", "pair"] {
        assert!(
            !renamed.wit.contains(leaked),
            "display name `{leaked}` leaked into WIT text:\n{}",
            renamed.wit
        );
    }

    assert_eq!(
        baseline.wit, renamed.wit,
        "a display rename must not move a single WIT byte"
    );
    let report = compare(&baseline, &renamed).unwrap();
    assert!(report.deltas.is_empty(), "{:?}", report.deltas);
    assert!(report.is_compatible());
}

/// A record *declaration* added to the world is the one additive delta:
/// nothing a baseline consumer binds to moved. Built by hand because an
/// admitted closure holds only records the signature reaches, so an
/// unreferenced record cannot be produced from source.
#[test]
fn an_added_record_declaration_is_reported_but_compatible() {
    let baseline = projection(BASELINE);
    let mut candidate = baseline.clone();
    candidate.records.push(WitRecordV1 {
        source_term: "@15:wit_compat.newcomer<>".to_owned(),
        name: wit_name("@15:wit_compat.newcomer<>"),
        fields: vec![WitFieldV1 {
            source_field_id: "wit_compat.newcomer.only".to_owned(),
            name: wit_name("wit_compat.newcomer.only"),
            type_text: "s64".to_owned(),
        }],
    });
    let added = wit_name("@15:wit_compat.newcomer<>");

    let report = compare(&baseline, &candidate).unwrap();
    assert_eq!(
        kinds(&report),
        vec![format!("record-added {added} @15:wit_compat.newcomer<>")]
    );
    assert!(report.is_compatible());
    // `require_compatible` must still *return* the report, so an additive
    // change stays visible rather than becoming indistinguishable from "no
    // change at all".
    let gated = require_compatible(&baseline, &candidate).unwrap();
    assert_eq!(gated.deltas.len(), 1);

    // The symmetric direction is a removal, and a removal is breaking: a
    // consumer may already name that declaration.
    let reverse = compare(&candidate, &baseline).unwrap();
    assert_eq!(
        kinds(&reverse),
        vec![format!("record-removed {added} @15:wit_compat.newcomer<>")]
    );
    assert!(!reverse.is_compatible());
    assert_eq!(
        require_compatible(&candidate, &baseline).unwrap_err().code,
        INCOMPATIBLE_CANDIDATE
    );
}

// ---------------------------------------------------------------------
// The delta kinds issue #176 names
// ---------------------------------------------------------------------

#[test]
fn a_field_added_to_an_existing_record_is_breaking_and_never_called_additive() {
    let baseline = projection(BASELINE);
    let candidate = projection(FIELD_ADDED);
    let leaf = record_owning(&baseline, "wit_compat.leaf.head").name;
    let extra = wit_name("wit_compat.leaf.extra");

    let report = compare(&baseline, &candidate).unwrap();
    assert_eq!(
        kinds(&report),
        vec![format!("field-added {leaf} {extra} s32")]
    );
    assert!(
        !report.is_compatible(),
        "adding a field rewrites a Component Model record's canonical field \
         sequence; it is not additive the way a new declaration is"
    );
    assert_eq!(
        require_compatible(&baseline, &candidate).unwrap_err().code,
        INCOMPATIBLE_CANDIDATE
    );

    // The reverse direction is a removal of the same field, and nothing else.
    let reverse = compare(&candidate, &baseline).unwrap();
    assert_eq!(
        kinds(&reverse),
        vec![format!("field-removed {leaf} {extra} s32")]
    );
}

/// Reordering two fields changes neither id, type, nor count. Only a
/// comparator that actually tracks position can see it; one comparing sets,
/// or sorted name lists, would report nothing and call this compatible.
#[test]
fn reordering_two_fields_with_identical_ids_and_types_is_reported_and_breaking() {
    let baseline = projection(BASELINE);
    let candidate = projection(FIELDS_REORDERED);
    assert_ne!(
        baseline.wit, candidate.wit,
        "the two fixtures must really render differently"
    );

    let leaf = record_owning(&baseline, "wit_compat.leaf.head").name;
    let head = wit_name("wit_compat.leaf.head");
    let tag = wit_name("wit_compat.leaf.tag");
    let report = compare(&baseline, &candidate).unwrap();
    assert_eq!(
        kinds(&report),
        vec![
            format!("field-reordered {leaf} {head} 0 -> 1"),
            format!("field-reordered {leaf} {tag} 1 -> 0"),
        ]
    );
    assert!(!report.is_compatible());
    // No type or ownership change may be invented: both fields kept their
    // exact types, and `trail` kept its position.
    let rendered = report.render();
    assert!(!rendered.contains("field-type-changed"));
    assert!(!rendered.contains("field-ownership-changed"));
    assert!(!rendered.contains(&wit_name("wit_compat.leaf.trail")));
}

/// The delta that matters most for this compiler: a leaf crossing between a
/// by-value type and an owned resource handle moves cleanup responsibility
/// across the boundary. It must be its own delta kind, not an unclassified
/// string difference a reviewer has to decode.
#[test]
fn a_leaf_crossing_the_ownership_boundary_is_its_own_delta_kind() {
    let baseline = projection(BASELINE);
    let candidate = projection(OWNERSHIP_CHANGED);
    let leaf = record_owning(&baseline, "wit_compat.leaf.head").name;
    let head = wit_name("wit_compat.leaf.head");

    let report = compare(&baseline, &candidate).unwrap();
    assert_eq!(
        kinds(&report),
        vec![format!(
            "field-ownership-changed {leaf} {head} own<{OWNED_BYTES_RESOURCE}> -> s64"
        )]
    );
    assert!(!report.is_compatible());
    assert!(
        !report.render().contains("field-type-changed"),
        "an ownership crossing must never be demoted to a plain type change"
    );

    // Symmetric: the reverse edit brings cleanup responsibility back.
    let reverse = compare(&candidate, &baseline).unwrap();
    assert_eq!(
        kinds(&reverse),
        vec![format!(
            "field-ownership-changed {leaf} {head} s64 -> own<{OWNED_BYTES_RESOURCE}>"
        )]
    );
}

/// The negative control for the test above: a type change that stays on one
/// side of the ownership boundary must *not* be reported as an ownership
/// change. Without this, `FieldOwnershipChanged` could be emitted for every
/// type difference and the ownership test above would still pass.
#[test]
fn a_type_change_that_does_not_cross_the_ownership_boundary_is_not_an_ownership_change() {
    let baseline = projection(BASELINE);
    let candidate = projection(FIELD_RETYPED);
    let leaf = record_owning(&baseline, "wit_compat.leaf.tag").name;
    let tag = wit_name("wit_compat.leaf.tag");

    let report = compare(&baseline, &candidate).unwrap();
    assert_eq!(
        kinds(&report),
        vec![format!("field-type-changed {leaf} {tag} s64 -> f64")]
    );
    assert!(!report.is_compatible());
    assert!(baseline.uses_owned_bytes_resource && candidate.uses_owned_bytes_resource);
}

/// The world's `resource` declaration appearing or disappearing. Synthetic:
/// an admitted export takes its input by `own`, so every projection reachable
/// from source today declares the resource, and this classification would
/// otherwise be untested dead code.
#[test]
fn the_owned_bytes_resource_declaration_appearing_or_disappearing_is_breaking() {
    let baseline = projection(BASELINE);
    assert!(baseline.uses_owned_bytes_resource);
    let mut without = baseline.clone();
    without.uses_owned_bytes_resource = false;

    let removed = compare(&baseline, &without).unwrap();
    assert_eq!(
        kinds(&removed),
        vec![format!(
            "owned-bytes-resource-removed {OWNED_BYTES_RESOURCE}"
        )]
    );
    assert!(!removed.is_compatible());

    let added = compare(&without, &baseline).unwrap();
    assert_eq!(
        kinds(&added),
        vec![format!("owned-bytes-resource-added {OWNED_BYTES_RESOURCE}")]
    );
    assert!(!added.is_compatible());
}

/// Each of the five world identities is compared, and a change to any one of
/// them is breaking. Synthetic for the same reason: the package, interface
/// and world names are module constants no source program can vary.
#[test]
fn every_world_identity_is_compared_and_a_change_to_any_one_is_breaking() {
    let baseline = projection(BASELINE);

    let cases: Vec<(&str, WitTypeProjectionV1)> = vec![
        (
            "package",
            WitTypeProjectionV1 {
                package: "semaprax:other@0.1.0",
                ..baseline.clone()
            },
        ),
        (
            "interface",
            WitTypeProjectionV1 {
                interface: "other-types",
                ..baseline.clone()
            },
        ),
        (
            "world",
            WitTypeProjectionV1 {
                world: "other-world",
                ..baseline.clone()
            },
        ),
        (
            "input-type",
            WitTypeProjectionV1 {
                input_type: "spx-00".to_owned(),
                ..baseline.clone()
            },
        ),
        (
            "result-type",
            WitTypeProjectionV1 {
                result_type: "spx-00".to_owned(),
                ..baseline.clone()
            },
        ),
    ];
    for (subject, candidate) in cases {
        let report = compare(&baseline, &candidate).unwrap();
        assert_eq!(report.deltas.len(), 1, "{subject}: {:?}", report.deltas);
        assert!(
            report.deltas[0]
                .render()
                .starts_with(&format!("world-identity-changed {subject} ")),
            "{subject}: {}",
            report.deltas[0].render()
        );
        assert!(!report.is_compatible(), "{subject}");
    }
}

/// An insertion in the middle must not make every later shared field look
/// reordered: position is compared among the fields the two records share.
#[test]
fn an_insertion_does_not_report_every_later_shared_field_as_reordered() {
    let baseline = projection(BASELINE);
    let leaf_name = record_owning(&baseline, "wit_compat.leaf.head").name;
    let mut candidate = baseline.clone();
    let leaf = candidate
        .records
        .iter_mut()
        .find(|record| record.name == leaf_name)
        .expect("the clone has the same record");
    leaf.fields.insert(
        0,
        WitFieldV1 {
            source_field_id: "wit_compat.leaf.prefix".to_owned(),
            name: wit_name("wit_compat.leaf.prefix"),
            type_text: "s32".to_owned(),
        },
    );
    let prefix = wit_name("wit_compat.leaf.prefix");

    let report = compare(&baseline, &candidate).unwrap();
    assert_eq!(
        kinds(&report),
        vec![format!("field-added {leaf_name} {prefix} s32")],
        "the three pre-existing fields kept their relative order and must not \
         be reported as reordered"
    );
}

// ---------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------

#[test]
fn two_different_projection_schemas_are_refused_rather_than_compared() {
    let baseline = projection(BASELINE);
    let candidate = WitTypeProjectionV1 {
        schema: "semaprax.public-generic-type-grammar.v1.wit-projection.v2",
        ..baseline.clone()
    };
    let error = compare(&baseline, &candidate).unwrap_err();
    assert_eq!(error.code, SCHEMA_MISMATCH);
    assert_eq!(
        require_compatible(&baseline, &candidate).unwrap_err().code,
        SCHEMA_MISMATCH,
        "the gate must report the schema refusal, not demote it to \
         `incompatible`"
    );
    // Positive control: the same pair compares cleanly once the schemas
    // agree, so the refusal is the schema check and nothing else.
    compare(&baseline, &baseline).unwrap();
}

#[test]
fn a_report_over_the_delta_limit_is_refused_not_truncated() {
    let baseline = projection(BASELINE);
    let filler = |count: usize| {
        let mut wide = baseline.clone();
        for index in 0..count {
            wide.records.push(WitRecordV1 {
                source_term: format!("@15:wit_compat.filler{index}<>"),
                name: format!("spx-f{index:08x}"),
                fields: Vec::new(),
            });
        }
        wide
    };

    let error = compare(&filler(MAX_REPORTED_DELTAS + 1), &baseline).unwrap_err();
    assert_eq!(error.code, REPORT_CAPACITY);

    // Exactly at the limit is accepted, so the bound is the documented one
    // and not off by one in the permissive direction.
    let report = compare(&filler(MAX_REPORTED_DELTAS), &baseline).unwrap();
    assert_eq!(report.deltas.len(), MAX_REPORTED_DELTAS);
}

// ---------------------------------------------------------------------
// Determinism and rendering
// ---------------------------------------------------------------------

#[test]
fn the_rendered_report_is_deterministic_and_carries_every_delta_with_its_class() {
    let baseline = projection(BASELINE);
    let candidate = projection(OWNERSHIP_CHANGED);
    let first = compare(&baseline, &candidate).unwrap().render();
    let second = compare(&baseline, &candidate).unwrap().render();
    assert_eq!(first, second);

    let leaf = record_owning(&baseline, "wit_compat.leaf.head").name;
    let head = wit_name("wit_compat.leaf.head");
    let expected = format!(
        "schema: {WIT_COMPATIBILITY_SCHEMA}\n\
         projection-schema: {}\n\
         compatible: no\n\
         deltas: 1\n\
         breaking: field-ownership-changed {leaf} {head} own<{OWNED_BYTES_RESOURCE}> -> s64\n",
        baseline.schema
    );
    assert_eq!(first, expected);

    // A compatible report renders its class too, so "compatible" is a
    // rendered fact rather than the absence of lines.
    let mut additive = baseline.clone();
    additive.records.push(WitRecordV1 {
        source_term: "@15:wit_compat.newcomer<>".to_owned(),
        name: wit_name("@15:wit_compat.newcomer<>"),
        fields: Vec::new(),
    });
    let rendered = compare(&baseline, &additive).unwrap().render();
    assert!(rendered.contains("compatible: yes\n"));
    assert!(rendered.contains("\ncompatible: record-added "));
}
