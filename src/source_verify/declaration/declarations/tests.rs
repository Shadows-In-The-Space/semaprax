//! Regression coverage for the SPX-T268 `check_byte_data_declarations`
//! widening: a direct owned `string` case field (Owned String Variant v1)
//! and a drop-free Copy-closed nested-record case field (Copy Aggregate
//! Variant Payload v1, `is_admitted_copy_aggregate_variant_field`) may now
//! be declared as sibling case fields of the same variant. Before this
//! widening, `check_byte_data_declarations`'s `has_direct_string` branch
//! consulted only `owned_byte_record_copy_field_is_admitted` (direct Copy
//! scalars), so a variant combining the two -- each independently admitted
//! on its own -- was refused outright.

use std::path::Path;

fn codes(source: &str) -> Vec<&'static str> {
    let program = crate::parse(source, Path::new("declarations-t268-sibling.spx")).unwrap();
    crate::verify::verify(&program)
        .into_iter()
        .filter(|diagnostic| diagnostic.severity.is_error())
        .map(|diagnostic| diagnostic.code)
        .collect()
}

#[test]
fn owned_string_variant_admits_a_drop_free_copy_aggregate_sibling_case_field() {
    let source = r#"
module test.owned_string_variant_copy_aggregate_sibling;
@id("test.inner")
record Inner {
    @id("test.inner.x")
    x: i64,
}
@id("test.payload")
variant Payload {
    @id("test.payload.text")
    Text {
        @id("test.payload.text.value")
        value: string,
    },
    @id("test.payload.wrapped")
    Wrapped {
        @id("test.payload.wrapped.value")
        value: Inner,
    },
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    assert_eq!(codes(source), Vec::<&str>::new());
}

#[test]
fn owned_string_variant_still_refuses_a_sibling_field_that_itself_needs_drop() {
    // `Inner` here reaches an owned `Bytes` leaf, so it stays outside Copy
    // Aggregate Variant Payload v1 (which requires the referenced record to
    // need no drop at all) -- the widening above must not also admit this
    // shape. SPX-T268 must still fire, exactly as it does for this same
    // nested-owned-leaf shape without a co-declared `string` field
    // (`copy_aggregate_variant_payload_rejects_a_nested_owned_leaf` in
    // `tests/language/variants_semantics.rs`).
    let source = r#"
module test.owned_string_variant_owned_leaf_sibling;
@id("test.inner")
record Inner {
    @id("test.inner.data")
    data: Bytes,
}
@id("test.payload")
variant Payload {
    @id("test.payload.text")
    Text {
        @id("test.payload.text.value")
        value: string,
    },
    @id("test.payload.wrapped")
    Wrapped {
        @id("test.payload.wrapped.value")
        value: Inner,
    },
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let got = codes(source);
    assert!(got.contains(&"SPX-T268"), "{got:?}");
}

#[test]
fn owned_string_variant_still_refuses_a_class_sibling_case_field() {
    // Class Inheritance v1 is excluded from Copy Aggregate Variant Payload
    // v1 (upcast slicing has no meaning inside a tagged union), so a class
    // sibling must still be refused even alongside a direct `string` case
    // field.
    let source = r#"
module test.owned_string_variant_class_sibling;
@id("test.inner")
class Inner {
    @id("test.inner.x")
    x: i64,
}
@id("test.payload")
variant Payload {
    @id("test.payload.text")
    Text {
        @id("test.payload.text.value")
        value: string,
    },
    @id("test.payload.wrapped")
    Wrapped {
        @id("test.payload.wrapped.value")
        value: Inner,
    },
}
@id("app.main")
fn main() -> i64 { 0 }
"#;
    let got = codes(source);
    assert!(got.contains(&"SPX-T268"), "{got:?}");
}
