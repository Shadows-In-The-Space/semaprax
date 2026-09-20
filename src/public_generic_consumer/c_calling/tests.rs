use super::*;
use crate::public_generic_abi::carrier::{CarrierBindingV1, TargetProfile};
use crate::public_generic_abi::descriptor::{DescriptorV1, InstanceBinding};

fn descriptor_bytes() -> Vec<u8> {
    DescriptorV1::new("sample.transform", "transform", "sha256:1111111111111111111111111111111111111111111111111111111111111111", "sha256:2222222222222222222222222222222222222222222222222222222222222222", "sha256:3333333333333333333333333333333333333333333333333333333333333333", InstanceBinding { term: "@11:sample.pair<bytes,bool>".to_owned(), instance_digest: "sha256:4444444444444444444444444444444444444444444444444444444444444444".to_owned() }, InstanceBinding { term: "@11:sample.pair<bytes,i64>".to_owned(), instance_digest: "sha256:5555555555555555555555555555555555555555555555555555555555555555".to_owned() }).encode()
}

fn binding() -> NativeProviderBindingV1 {
    NativeProviderBindingV1::new(
        CarrierBindingV1::new(
            "sha256:7777777777777777777777777777777777777777777777777777777777777777",
            TargetProfile::NativeC11,
            "runtime:native-c11-fixture-issue-158",
        ),
        "sha256:8888888888888888888888888888888888888888888888888888888888888888",
        "spx_pg_endpoint_reverse_bytes_v1",
        "semaprax-0.4.1",
    )
}

fn shapes() -> (RecordShape, RecordShape) {
    let input = RecordShape::new(vec![
        OwnedByteField::new("c_calling.head"),
        OwnedByteField::new("c_calling.tail"),
    ]);
    let output = RecordShape::new(vec![
        OwnedByteField::new("c_calling.head"),
        OwnedByteField::new("c_calling.tail"),
    ]);
    (input, output)
}

fn generate() -> CallingConsumer {
    let (input, output) = shapes();
    generate_c_calling_consumer(&descriptor_bytes(), &binding(), &input, &output)
        .expect("a well-formed shape must generate")
}

#[test]
fn regeneration_is_byte_identical() {
    let first = generate();
    let second = generate();
    assert_eq!(first.files(), second.files());
}

#[test]
fn emits_the_expected_file_set_in_a_stable_order() {
    let consumer = generate();
    let names: Vec<&str> = consumer
        .files()
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "spx_pg_v1.h",
            "spx_pg_calling_consumer.h",
            "spx_pg_calling_consumer.c",
            "round_trip.c",
        ]
    );
}

#[test]
fn every_file_is_lf_only_and_ends_with_a_trailing_newline() {
    for (name, contents) in generate().files() {
        assert!(!contents.contains('\r'), "{name} contains a CR byte");
        assert!(
            contents.ends_with('\n'),
            "{name} does not end with a newline"
        );
    }
}

#[test]
fn shipped_header_is_byte_identical_to_the_frozen_native_abi_header() {
    let consumer = generate();
    let (_, header) = consumer
        .files()
        .iter()
        .find(|(name, _)| name == "spx_pg_v1.h")
        .expect("spx_pg_v1.h must be generated");
    assert_eq!(header, &HEADER_V1.replace("\r\n", "\n"));
}

/// "Native handles are private" and "keep the surface clean enough to
/// wrap" (issue #158, for #159): the generated public header never mentions
/// a native ABI type, and depends on nothing beyond the two standard headers
/// it names.
#[test]
fn consumer_header_names_no_native_abi_type_and_only_two_includes() {
    let consumer = generate();
    let (_, header) = consumer
        .files()
        .iter()
        .find(|(name, _)| name == CONSUMER_HEADER_FILE_NAME)
        .expect("the consumer header must be generated");
    for forbidden in [
        "spx_pg_provider_v1",
        "spx_pg_value_v1",
        "spx_pg_result_v1",
        "spx_pg_v1.h",
    ] {
        assert!(
            !header.contains(forbidden),
            "the public header must not mention {forbidden}"
        );
    }
    let include_lines: Vec<&str> = header
        .lines()
        .filter(|line| line.trim_start().starts_with("#include"))
        .collect();
    assert_eq!(
        include_lines,
        vec!["#include <stddef.h>", "#include <stdint.h>"]
    );
}

/// The implementation file is the one and only generated file allowed to
/// depend on the native ABI header, and it must actually depend on it (never
/// restate its declarations independently).
#[test]
fn only_the_source_file_includes_the_native_abi_header() {
    let consumer = generate();
    for (name, contents) in consumer.files() {
        let includes_native_header = contents.contains("#include \"spx_pg_v1.h\"");
        if name == CONSUMER_SOURCE_FILE_NAME {
            assert!(
                includes_native_header,
                "{CONSUMER_SOURCE_FILE_NAME} must #include the native ABI header"
            );
        } else if name != HEADER_FILE_NAME {
            assert!(
                !includes_native_header,
                "{name} must not include the native ABI header"
            );
        }
    }
}

#[test]
fn field_names_are_derived_from_identity_bytes_not_display_text() {
    let field = OwnedByteField::new("some.declaration.identity");
    assert_eq!(
        field_name(&field),
        format!("field_{}", identifier("some.declaration.identity"))
    );
    let other = OwnedByteField::new("some.other.identity");
    assert_ne!(field_name(&field), field_name(&other));
}

#[test]
fn duplicate_field_identity_in_one_record_is_rejected() {
    let input = RecordShape::new(vec![
        OwnedByteField::new("same.identity"),
        OwnedByteField::new("same.identity"),
    ]);
    let output = RecordShape::new(vec![OwnedByteField::new("x"), OwnedByteField::new("y")]);
    let error =
        generate_c_calling_consumer(&descriptor_bytes(), &binding(), &input, &output).unwrap_err();
    assert_eq!(
        error,
        ShapeError::DuplicateFieldIdentity {
            record: "Input",
            identity: "same.identity".to_owned(),
        }
    );
}

#[test]
fn mismatched_leaf_counts_are_rejected() {
    let input = RecordShape::new(vec![OwnedByteField::new("only-one")]);
    let output = RecordShape::new(vec![OwnedByteField::new("a"), OwnedByteField::new("b")]);
    let error =
        generate_c_calling_consumer(&descriptor_bytes(), &binding(), &input, &output).unwrap_err();
    assert_eq!(
        error,
        ShapeError::LeafCountMismatch {
            input: 1,
            output: 2,
        }
    );
}

#[test]
fn embeds_the_exact_trusted_descriptor_and_binding_bytes() {
    let consumer = generate();
    let (_, source) = consumer
        .files()
        .iter()
        .find(|(name, _)| name == CONSUMER_SOURCE_FILE_NAME)
        .expect("the consumer source must be generated");
    for byte in &descriptor_bytes() {
        let needle = format!("0x{byte:02x}");
        assert!(
            source.contains(&needle),
            "the source must embed byte {needle} of the trusted descriptor"
        );
    }
    let binding_bytes = binding().encode();
    for byte in &binding_bytes {
        let needle = format!("0x{byte:02x}");
        assert!(
            source.contains(&needle),
            "the source must embed byte {needle} of the trusted binding"
        );
    }
}

#[test]
fn descriptor_replay_is_bounded_and_field_structured() {
    let consumer = generate();
    let source = &consumer
        .files()
        .iter()
        .find(|(name, _)| name == CONSUMER_SOURCE_FILE_NAME)
        .unwrap()
        .1;
    assert!(source.contains("spx_pg_ccc_parse_descriptor_v1"));
    assert!(source.contains("spx_pg_ccc_descriptor_fields"));
    assert!(source.contains("for (size_t field = 0; field < 12u; field += 1u)"));
    assert!(!source.contains(
        "spx_pg_ccc_bytes_equal(descriptor_bytes, descriptor_len, spx_pg_trusted_descriptor_bytes"
    ));
}

#[test]
fn no_host_path_or_checkout_specific_text_survives_generation() {
    for (name, contents) in generate().files() {
        assert!(
            !contents.contains("/Users/") && !contents.contains("C:\\"),
            "{name} must not embed a checkout-specific host path"
        );
        assert!(
            !contents.contains("{{") && !contents.contains("}}"),
            "{name} must not leave a surviving template placeholder"
        );
    }
}

#[test]
fn field_count_and_field_lists_scale_with_the_shape() {
    let input = RecordShape::new(vec![
        OwnedByteField::new("one"),
        OwnedByteField::new("two"),
        OwnedByteField::new("three"),
    ]);
    let output = input.clone();
    let consumer =
        generate_c_calling_consumer(&descriptor_bytes(), &binding(), &input, &output).unwrap();
    let (_, source) = consumer
        .files()
        .iter()
        .find(|(name, _)| name == CONSUMER_SOURCE_FILE_NAME)
        .unwrap();
    assert!(source.contains("#define FIELD_COUNT 3"));
    let (_, header) = consumer
        .files()
        .iter()
        .find(|(name, _)| name == CONSUMER_HEADER_FILE_NAME)
        .unwrap();
    for field in &input.fields {
        assert!(header.contains(&field_name(field)));
    }
}

#[test]
fn empty_trusted_bytes_render_a_valid_c_array_literal() {
    let (input, output) = shapes();
    let consumer = generate_c_calling_consumer(b"", &binding(), &input, &output).unwrap();
    let (_, source) = consumer
        .files()
        .iter()
        .find(|(name, _)| name == CONSUMER_SOURCE_FILE_NAME)
        .unwrap();
    assert!(source.contains("const uint8_t spx_pg_trusted_descriptor_bytes[] = {0};"));
    assert!(!source.contains("uint8_t spx_pg_trusted_descriptor_bytes[] = {};"));
}

#[test]
fn executable_shape_bounds_are_exact_and_do_not_emit_empty_or_oversized_records() {
    for count in [0usize, 257] {
        let shape = RecordShape::new(
            (0..count)
                .map(|index| OwnedByteField::new(format!("bound.field{index}")))
                .collect(),
        );
        assert_eq!(
            generate_c_calling_consumer(&descriptor_bytes(), &binding(), &shape, &shape)
                .unwrap_err(),
            ShapeError::LeafCountOutOfBounds { count }
        );
    }
    let shape = RecordShape::new(
        (0..256)
            .map(|index| OwnedByteField::new(format!("bound.field{index}")))
            .collect(),
    );
    assert!(generate_c_calling_consumer(&descriptor_bytes(), &binding(), &shape, &shape).is_ok());
}

#[test]
fn explicit_settlement_api_preserves_status_numbers_and_hides_native_handles() {
    let consumer = generate();
    let header = &consumer
        .files()
        .iter()
        .find(|(name, _)| name == CONSUMER_HEADER_FILE_NAME)
        .unwrap()
        .1;
    let source = &consumer
        .files()
        .iter()
        .find(|(name, _)| name == CONSUMER_SOURCE_FILE_NAME)
        .unwrap()
        .1;
    assert!(header.contains("SPX_PG_CONSUMER_NULL_ARGUMENT = 8"));
    assert!(header.contains("SPX_PG_CONSUMER_RELEASE_FAILED = 9"));
    assert!(header.contains("spx_pg_consumer_transform_with_settlement"));
    assert!(header.contains("spx_pg_consumer_close_checked"));
    assert!(source.contains("outcome.primary_status == SPX_PG_CONSUMER_OK"));
    assert!(source.contains("required > SPX_PG_CCC_MAX_FRAME_BYTES"));
}
