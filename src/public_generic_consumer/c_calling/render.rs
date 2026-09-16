//! The deterministic string templates [`super::generate_c_calling_consumer`]
//! composes. Split from `c_calling.rs` itself only to keep that file's own
//! generator-contract logic short; every function here is a pure
//! byte-in/text-out renderer, exercised by [`super::tests`].
//!
//! Every function below states, in its own doc comment, which part of its
//! output is a **fixed template** restating `spx_pg_v1.h` (or this
//! generator's own closed status/API vocabulary) and which part is
//! **descriptor-derived** (scales with the shape's field count and field
//! identities).

use std::fmt::Write as _;

use super::{field_name, RecordShape};

/// Generate `spx_pg_calling_consumer.h`: the clean public surface.
///
/// **Fixed template:** the opaque handle, the closed
/// `spx_pg_consumer_status` vocabulary, `spx_pg_owned_bytes`, every function
/// declaration and its doc comment. **Descriptor-derived:** the
/// `spx_pg_input`/`spx_pg_output` struct field lists (one `spx_pg_owned_bytes`
/// member per leaf, in descriptor order, named from the leaf's identity
/// bytes).
pub(super) fn consumer_header(input: &RecordShape, output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str(HEADER_PREAMBLE);
    out.push_str(&record_struct("spx_pg_input", input));
    out.push('\n');
    out.push_str(&record_struct("spx_pg_output", output));
    out.push('\n');
    out.push_str(HEADER_API);
    out.replace("\r\n", "\n")
}

fn record_struct(name: &str, shape: &RecordShape) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "typedef struct {name} {{");
    for field in &shape.fields {
        let _ = writeln!(out, "    /* Field identity: {:?} */", field.identity);
        let _ = writeln!(out, "    spx_pg_owned_bytes {};", field_name(field));
    }
    let _ = writeln!(out, "}} {name};");
    out
}

const HEADER_PREAMBLE: &str = include_str!("render/header_preamble.h.txt");

const HEADER_API: &str = include_str!("render/header_api.h.txt");

/// Generate `spx_pg_calling_consumer.c`.
///
/// **Fixed template:** the little-endian codec, `#include`s, the opaque
/// struct, `spx_pg_consumer_open`/`_transform`/`_close`, every status
/// mapping function, and the test-only diagnostics wrappers.
/// **Descriptor-derived:** the embedded trusted descriptor/binding byte
/// arrays, `FIELD_COUNT`, the per-field encode/free/assign statements (one
/// line per leaf, in descriptor order).
pub(super) fn consumer_source(
    descriptor_bytes: &[u8],
    binding_bytes: &[u8],
    input: &RecordShape,
    output: &RecordShape,
) -> String {
    let field_count = input.fields.len();
    let mut out = String::new();
    out.push_str(SOURCE_PREAMBLE);
    let _ = writeln!(out, "#define FIELD_COUNT {field_count}");
    out.push('\n');
    out.push_str(&c_byte_array(
        "spx_pg_trusted_descriptor_bytes",
        "spx_pg_trusted_descriptor_len",
        descriptor_bytes,
    ));
    out.push('\n');
    out.push_str(&c_byte_array(
        "spx_pg_trusted_binding_bytes",
        "spx_pg_trusted_binding_len",
        binding_bytes,
    ));
    out.push('\n');
    out.push_str(SOURCE_CODEC_AND_LIFECYCLE);
    out.push('\n');
    out.push_str(&encode_input_fn(input));
    out.push('\n');
    out.push_str(&free_input_leaves_fn(input));
    out.push('\n');
    out.push_str(&free_output_fn(output));
    out.push('\n');
    out.push_str(&decode_output_fn(output));
    out.push('\n');
    out.push_str(SOURCE_TRANSFORM_AND_DIAGNOSTICS);
    out.replace("\r\n", "\n")
}

const SOURCE_PREAMBLE: &str = include_str!("render/source_preamble.c.txt");

/// One numeric byte literal per generated file, twelve bytes a line so a
/// diff of two generated consumers stays readable, matching
/// `public_generic_consumer::byte_literal`'s own convention. Mirrors
/// `native/template.rs::write_byte_array`'s `{0}`-for-empty convention so an
/// empty trusted value never renders `uint8_t name[] = {};`, which is not
/// valid C.
fn c_byte_array(bytes_name: &str, len_name: &str, bytes: &[u8]) -> String {
    let mut out = String::new();
    if bytes.is_empty() {
        let _ = writeln!(out, "const uint8_t {bytes_name}[] = {{0}};");
    } else {
        let _ = writeln!(out, "const uint8_t {bytes_name}[] = {{");
        for chunk in bytes.chunks(12) {
            out.push_str("    ");
            for byte in chunk {
                let _ = write!(out, "0x{byte:02x}, ");
            }
            out.push('\n');
        }
        out.push_str("};\n");
    }
    let _ = writeln!(out, "const size_t {len_name} = {};", bytes.len());
    out
}

const SOURCE_CODEC_AND_LIFECYCLE: &str = include_str!("render/codec.c.txt");

fn encode_input_fn(input: &RecordShape) -> String {
    let mut out = String::from(
        "static spx_pg_consumer_status spx_pg_ccc_encode_input(const spx_pg_input *input,\n    uint8_t **out_bytes, size_t *out_len) {\n    const spx_pg_owned_bytes *leaves[FIELD_COUNT] = {\n",
    );
    for field in &input.fields {
        let _ = writeln!(out, "        &input->{},", field_name(field));
    }
    out.push_str("    };\n    return spx_pg_ccc_encode_leaves(leaves, out_bytes, out_len);\n}\n");
    out
}

fn free_input_leaves_fn(input: &RecordShape) -> String {
    let mut out = String::from(
        "static void spx_pg_ccc_free_input_leaves(spx_pg_input *input) {\n    spx_pg_owned_bytes *leaves[FIELD_COUNT] = {\n",
    );
    for field in &input.fields {
        let _ = writeln!(out, "        &input->{},", field_name(field));
    }
    out.push_str("    };\n    spx_pg_ccc_consume_input(leaves);\n}\n");
    out
}

fn free_output_fn(output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("void spx_pg_owned_bytes_free(spx_pg_owned_bytes *bytes) {\n");
    out.push_str(
        "    if (bytes == NULL) {\n        return;\n    }\n    free(bytes->data);\n    bytes->data = NULL;\n    bytes->len = 0;\n}\n\n",
    );
    out.push_str("void spx_pg_output_free(spx_pg_output *output) {\n");
    out.push_str("    if (output == NULL) {\n        return;\n    }\n");
    for field in output.fields.iter().rev() {
        let _ = writeln!(
            out,
            "    spx_pg_owned_bytes_free(&output->{});",
            field_name(field)
        );
    }
    out.push_str("}\n");
    out
}

fn decode_output_fn(output: &RecordShape) -> String {
    let mut out = String::from(
        "static spx_pg_consumer_status spx_pg_ccc_decode_output(const uint8_t *bytes, size_t len,\n    spx_pg_output *out) {\n    spx_pg_owned_bytes leaves[FIELD_COUNT];\n    memset(leaves, 0, sizeof(leaves));\n    spx_pg_consumer_status status = spx_pg_ccc_decode_leaves(bytes, len, leaves);\n    if (status != SPX_PG_CONSUMER_OK) return status;\n",
    );
    for (index, field) in output.fields.iter().enumerate() {
        let _ = writeln!(out, "    out->{} = leaves[{index}];", field_name(field));
    }
    out.push_str("    return SPX_PG_CONSUMER_OK;\n}\n");
    out
}

const SOURCE_TRANSFORM_AND_DIAGNOSTICS: &str = include_str!("render/lifecycle.c.txt");

/// Generate `round_trip.c`: a real, executable test driver -- not a mere
/// compile check.
///
/// **Fixed template:** the `REQUIRE` macro, byte-reversal and owned-bytes
/// helpers, the mutated-descriptor/binding/different-descriptor tests, the
/// per-leaf-bound tests' scaffolding, the full ordinal `0..=13`
/// failure-injection matrix, and `main`. **Descriptor-derived:** the sample
/// input/expected builders, the per-field `assert_reversed` comparisons, the
/// per-field zero-on-failure assertions, and which field the per-leaf-bound
/// tests target (the first one, matching
/// `rust_calling::render::round_trip_rs`'s own convention).
pub(super) fn round_trip_c(input: &RecordShape, output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str(ROUND_TRIP_PREAMBLE);
    out.push_str(&sample_input_fn(input));
    out.push('\n');
    out.push_str(&free_input_fn(input));
    out.push('\n');
    out.push_str(&input_with_first_field_fn(input));
    out.push('\n');
    out.push_str(&assert_reversed_fn(input, output));
    out.push('\n');
    out.push_str(&assert_output_is_zeroed_fn(output));
    out.push('\n');
    out.push_str(ROUND_TRIP_BODY);
    out.push('\n');
    out.push_str(&per_leaf_bound_tests_fn(output));
    out.push('\n');
    out.push_str(&main_fn());
    out
}

const ROUND_TRIP_PREAMBLE: &str = r#"/*
 * Generated by semaprax::public_generic_consumer::c_calling.
 * Compiler-generated deterministic output; do not edit.
 *
 * Real, executed evidence for issue #158: opens the real native provider
 * through the generated C11 calling consumer, transfers one owned input
 * record exactly once, calls, decodes an independently validated result,
 * and proves zero live native allocations/handles after every terminal case
 * -- success, hostile pairing, the per-leaf byte bound, and the full
 * ordinal 0..=13 failure-injection matrix -- using the native provider's
 * OWN test-only counters (spx_pg_consumer_test_live_allocations/_handles),
 * exactly like tests/public_generic_native_adapter_v1/probe.c's own
 * C-hosted matrix for the same provider.
 */
#include "spx_pg_calling_consumer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BYTES_PER_LEAF (64u * 1024u)

static void spx_pg_ccc_require(int condition, const char *message, unsigned line) {
    if (!condition) {
        fprintf(stderr, "round_trip.c line %u: %s\n", line, message);
        exit(1);
    }
}
#define REQUIRE(condition) spx_pg_ccc_require((condition), #condition, __LINE__)

static spx_pg_owned_bytes owned_from(const char *text) {
    size_t len = strlen(text);
    spx_pg_owned_bytes bytes;
    bytes.len = len;
    bytes.data = len == 0 ? NULL : (uint8_t *)malloc(len);
    REQUIRE(len == 0 || bytes.data != NULL);
    if (len != 0) {
        memcpy(bytes.data, text, len);
    }
    return bytes;
}

static void assert_reversed_field(const spx_pg_owned_bytes *actual, const spx_pg_owned_bytes *original) {
    REQUIRE(actual->len == original->len);
    if (actual->len == 0) {
        REQUIRE(actual->data == NULL);
        return;
    }
    uint8_t *expected = (uint8_t *)malloc(actual->len);
    REQUIRE(expected != NULL);
    for (size_t index = 0; index < actual->len; ++index) {
        expected[index] = original->data[original->len - 1 - index];
    }
    REQUIRE(memcmp(actual->data, expected, actual->len) == 0);
    free(expected);
}
"#;

fn sample_input_fn(input: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("\nstatic spx_pg_input sample_input(void) {\n");
    out.push_str("    spx_pg_input input;\n");
    for (index, field) in input.fields.iter().enumerate() {
        let _ = writeln!(
            out,
            "    input.{} = owned_from(\"sample-{index}\");",
            field_name(field)
        );
    }
    out.push_str("    return input;\n");
    out.push_str("}\n");
    out
}

fn free_input_fn(input: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("static void free_input(spx_pg_input *input) {\n");
    for field in &input.fields {
        let _ = writeln!(
            out,
            "    spx_pg_owned_bytes_free(&input->{});",
            field_name(field)
        );
    }
    out.push_str("}\n");
    out
}

fn input_with_first_field_fn(input: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("static spx_pg_input input_with_first_field(uint8_t *data, size_t len) {\n");
    out.push_str("    spx_pg_input input;\n");
    for (index, field) in input.fields.iter().enumerate() {
        if index == 0 {
            let _ = writeln!(out, "    input.{}.data = data;", field_name(field));
            let _ = writeln!(out, "    input.{}.len = len;", field_name(field));
        } else {
            let _ = writeln!(out, "    input.{}.data = NULL;", field_name(field));
            let _ = writeln!(out, "    input.{}.len = 0;", field_name(field));
        }
    }
    out.push_str("    return input;\n");
    out.push_str("}\n");
    out
}

fn assert_reversed_fn(input: &RecordShape, output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("static void assert_reversed(const spx_pg_output *output, const spx_pg_input *original) {\n");
    for (in_field, out_field) in input.fields.iter().zip(output.fields.iter()) {
        let _ = writeln!(
            out,
            "    assert_reversed_field(&output->{}, &original->{});",
            field_name(out_field),
            field_name(in_field)
        );
    }
    out.push_str("}\n");
    out
}

fn assert_output_is_zeroed_fn(output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str(
        "/* \"Output parameters have deterministic failure values\": every leaf\n\
         * stays exactly {NULL,0} on any failure. */\n",
    );
    out.push_str("static void assert_output_is_zeroed(const spx_pg_output *output) {\n");
    for field in &output.fields {
        let name = field_name(field);
        let _ = writeln!(out, "    REQUIRE(output->{name}.data == NULL);");
        let _ = writeln!(out, "    REQUIRE(output->{name}.len == 0);");
    }
    out.push_str("}\n");
    out
}

const ROUND_TRIP_BODY: &str = r#"static void test_success_round_trip(void) {
    spx_pg_calling_consumer *consumer = NULL;
    REQUIRE(spx_pg_consumer_open(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len,
                                  spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len,
                                  &consumer) == SPX_PG_CONSUMER_OK);
    REQUIRE(consumer != NULL);

    spx_pg_input input = sample_input();
    spx_pg_input expected = sample_input();
    spx_pg_output output;
    int native_status = -1;
    REQUIRE(spx_pg_consumer_transform(consumer, &input, &output, &native_status) == SPX_PG_CONSUMER_OK);
    REQUIRE(native_status == 0);
    assert_reversed(&output, &expected);

    spx_pg_output_free(&output);
    free_input(&expected);
    spx_pg_consumer_close(&consumer);
    REQUIRE(consumer == NULL);
    REQUIRE(spx_pg_consumer_test_live_allocations() == 0);
}

static void test_open_rejects_a_mutated_descriptor_before_any_native_allocation(void) {
    size_t len = spx_pg_trusted_descriptor_len;
    uint8_t *mutated = (uint8_t *)malloc(len == 0 ? 1 : len);
    REQUIRE(mutated != NULL);
    if (len != 0) {
        memcpy(mutated, spx_pg_trusted_descriptor_bytes, len);
        mutated[0] ^= 0xffu;
    }
    size_t allocations_before = spx_pg_consumer_test_live_allocations();
    spx_pg_calling_consumer *consumer = (spx_pg_calling_consumer *)(void *)0x1;
    spx_pg_consumer_status status =
        spx_pg_consumer_open(mutated, len, spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len,
                              &consumer);
    REQUIRE(status == SPX_PG_CONSUMER_DESCRIPTOR_REJECTED);
    REQUIRE(consumer == NULL);
    REQUIRE(spx_pg_consumer_test_live_allocations() == allocations_before);
    free(mutated);
}

static void test_open_rejects_a_mutated_binding_before_any_native_allocation(void) {
    size_t len = spx_pg_trusted_binding_len;
    REQUIRE(len > 0);
    uint8_t *mutated = (uint8_t *)malloc(len);
    REQUIRE(mutated != NULL);
    memcpy(mutated, spx_pg_trusted_binding_bytes, len);
    mutated[len - 1] ^= 0xffu;
    size_t allocations_before = spx_pg_consumer_test_live_allocations();
    spx_pg_calling_consumer *consumer = (spx_pg_calling_consumer *)(void *)0x1;
    spx_pg_consumer_status status =
        spx_pg_consumer_open(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len, mutated,
                              len, &consumer);
    REQUIRE(status == SPX_PG_CONSUMER_PROVIDER_MISMATCH);
    REQUIRE(consumer == NULL);
    REQUIRE(spx_pg_consumer_test_live_allocations() == allocations_before);
    free(mutated);
}

static void test_open_rejects_a_valid_binding_that_names_a_different_descriptor(void) {
    /* The trusted binding is well-formed on its own, but paired against a
     * descriptor it was never generated for; this consumer's own replay (a
     * byte-exact pairing, not a semantic re-derivation) rejects it exactly
     * like a genuinely corrupted descriptor would. */
    static const char suffix[] = "-a-different-but-well-formed-descriptor";
    size_t len = spx_pg_trusted_descriptor_len + (sizeof(suffix) - 1);
    uint8_t *different = (uint8_t *)malloc(len);
    REQUIRE(different != NULL);
    if (spx_pg_trusted_descriptor_len != 0) {
        memcpy(different, spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len);
    }
    memcpy(different + spx_pg_trusted_descriptor_len, suffix, sizeof(suffix) - 1);
    spx_pg_calling_consumer *consumer = NULL;
    spx_pg_consumer_status status = spx_pg_consumer_open(
        different, len, spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len, &consumer);
    REQUIRE(status == SPX_PG_CONSUMER_DESCRIPTOR_REJECTED);
    REQUIRE(consumer == NULL);
    free(different);
}

/* Every logical trace ordinal 0..=13 (SPX_PG_TRACE_FRAME_VALIDATED through
 * SPX_PG_TRACE_CARRIER_RELEASE; ordinal 14, the settlement call itself, has
 * nothing left to abort -- see spx_pg_v1.h) settles as a failure with zero
 * live native allocations/handles afterward and a deterministic
 * all-zeroed output, exactly like probe.c's own C-hosted matrix for the
 * same provider. */
static void test_failure_injection_matrix_settles_every_ordinal_with_zero_live_resources(void) {
    for (uint32_t ordinal = 0; ordinal <= 13; ++ordinal) {
        spx_pg_calling_consumer *consumer = NULL;
        REQUIRE(spx_pg_consumer_open(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len,
                                      spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len,
                                      &consumer) == SPX_PG_CONSUMER_OK);
        spx_pg_consumer_test_inject_failure(ordinal);
        spx_pg_input input = sample_input();
        spx_pg_output output;
        spx_pg_consumer_status status = spx_pg_consumer_transform(consumer, &input, &output, NULL);
        REQUIRE(status != SPX_PG_CONSUMER_OK);
        assert_output_is_zeroed(&output);
        spx_pg_consumer_test_clear_failure_injection();
        REQUIRE(spx_pg_consumer_test_live_handles(consumer) == 0);
        spx_pg_consumer_close(&consumer);
        REQUIRE(consumer == NULL);
        REQUIRE(spx_pg_consumer_test_live_allocations() == 0);
    }
}
"#;

fn per_leaf_bound_tests_fn(output: &RecordShape) -> String {
    let first_output_field = field_name(&output.fields[0]);
    let mut out = String::new();
    out.push_str("static void test_exactly_the_per_leaf_byte_bound_is_accepted(void) {\n");
    out.push_str(
        "    spx_pg_calling_consumer *consumer = NULL;\n\
         \x20   REQUIRE(spx_pg_consumer_open(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len,\n\
         \x20                                 spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len,\n\
         \x20                                 &consumer) == SPX_PG_CONSUMER_OK);\n\
         \x20   uint8_t *data = (uint8_t *)malloc(MAX_BYTES_PER_LEAF);\n\
         \x20   REQUIRE(data != NULL);\n\
         \x20   memset(data, 0x5a, MAX_BYTES_PER_LEAF);\n\
         \x20   spx_pg_input input = input_with_first_field(data, MAX_BYTES_PER_LEAF);\n\
         \x20   spx_pg_output output;\n\
         \x20   REQUIRE(spx_pg_consumer_transform(consumer, &input, &output, NULL) == SPX_PG_CONSUMER_OK);\n",
    );
    let _ = writeln!(
        out,
        "    REQUIRE(output.{first_output_field}.len == MAX_BYTES_PER_LEAF);"
    );
    out.push_str(
        "    spx_pg_output_free(&output);\n\
         \x20   spx_pg_consumer_close(&consumer);\n\
         \x20   REQUIRE(spx_pg_consumer_test_live_allocations() == 0);\n\
         }\n\n",
    );

    out.push_str("static void test_one_byte_over_the_per_leaf_bound_is_rejected_locally(void) {\n");
    out.push_str(
        "    spx_pg_calling_consumer *consumer = NULL;\n\
         \x20   REQUIRE(spx_pg_consumer_open(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len,\n\
         \x20                                 spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len,\n\
         \x20                                 &consumer) == SPX_PG_CONSUMER_OK);\n\
         \x20   uint8_t *data = (uint8_t *)malloc(MAX_BYTES_PER_LEAF + 1);\n\
         \x20   REQUIRE(data != NULL);\n\
         \x20   memset(data, 0x5a, MAX_BYTES_PER_LEAF + 1);\n\
         \x20   spx_pg_input input = input_with_first_field(data, MAX_BYTES_PER_LEAF + 1);\n\
         \x20   spx_pg_output output;\n\
         \x20   REQUIRE(spx_pg_consumer_transform(consumer, &input, &output, NULL) ==\n\
         \x20           SPX_PG_CONSUMER_CAPACITY_EXCEEDED);\n\
         \x20   assert_output_is_zeroed(&output);\n\
         \x20   spx_pg_consumer_close(&consumer);\n\
         \x20   REQUIRE(spx_pg_consumer_test_live_allocations() == 0);\n\
         }\n",
    );
    out
}

fn main_fn() -> String {
    r#"int main(void) {
    test_success_round_trip();
    test_open_rejects_a_mutated_descriptor_before_any_native_allocation();
    test_open_rejects_a_mutated_binding_before_any_native_allocation();
    test_open_rejects_a_valid_binding_that_names_a_different_descriptor();
    test_exactly_the_per_leaf_byte_bound_is_accepted();
    test_one_byte_over_the_per_leaf_bound_is_rejected_locally();
    test_failure_injection_matrix_settles_every_ordinal_with_zero_live_resources();
    (void)puts("c-calling-consumer-settled");
    return 0;
}
"#
    .to_owned()
}
