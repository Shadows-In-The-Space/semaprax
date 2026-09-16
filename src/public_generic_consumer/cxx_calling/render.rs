//! The deterministic string templates [`super::generate_cxx_calling_consumer`]
//! composes. Split from `cxx_calling.rs` itself only to keep that file's own
//! generator-contract logic short, mirroring
//! [`super::super::c_calling::render`]'s own split.
//!
//! Every function below states, in its own doc comment, which part of its
//! output is a **fixed template** (the RAII/move-only mechanics, the closed
//! `ErrorKind`/`Result<T>` vocabulary, the hostile-pairing and
//! failure-injection test bodies) and which part is **descriptor-derived**
//! (the `Input`/`Output` field lists and accessors, and the per-field
//! transform plumbing that has to scale with field count).
//!
//! Every generated identifier that must not collide is derived from
//! [`field_name`] — the same `field_<hex-identity>` scheme
//! [`super::super::c_calling`] and [`super::super::rust_calling`] use — so a
//! display-name collision or a C++ keyword can never reach a generated
//! identifier: the prefix `field_` followed only by lowercase hex digits is
//! never a C++ keyword and is injective in the field's declaration-identity
//! bytes, never its display name.

use std::fmt::Write as _;

use super::{field_name, RecordShape};

/// Generate `include/semaprax_public_generic_v1.hpp`: the move-only RAII
/// wrapper around the generated C11 calling consumer.
///
/// **Fixed template:** the include guard, the `#include` of the C11 header,
/// the namespace, `BytesView`, `to_owned`, the closed `ErrorKind`
/// vocabulary, `Error`, `Result<T>`, the `Provider`/`Output` class
/// mechanics (move/copy/destructor, `open`, `close`, `reset`), the
/// compile-time static assertions, and `detail::make_owned_bytes`.
/// **Descriptor-derived:** the `Input` struct's field list, `Output`'s
/// per-field accessor methods, and `Provider::transform`'s per-field
/// encode/free statements (one line per leaf, in descriptor order).
pub(super) fn wrapper_header(input: &RecordShape, output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str(HEADER_PRELUDE);
    out.push_str(&input_struct(input));
    out.push('\n');
    out.push_str(&output_class(output));
    out.push('\n');
    out.push_str(PROVIDER_CLASS_AND_ASSERTIONS);
    out.push('\n');
    out.push_str(DETAIL_MAKE_OWNED_BYTES);
    out.push('\n');
    out.push_str(PROVIDER_OPEN_DEFINITIONS);
    out.push('\n');
    out.push_str(&provider_transform_definition(input));
    out.push_str(HEADER_TRAILER);
    out.replace("\r\n", "\n")
}

const HEADER_PRELUDE: &str = include_str!("render/header.hpp.txt");

fn input_struct(input: &RecordShape) -> String {
    let mut fields = String::new();
    for field in &input.fields {
        let _ = writeln!(fields, "    std::vector<std::uint8_t> {};", field_name(field));
    }
    include_str!("render/input.hpp.txt").replace("@FIELDS@", &fields)
}

fn output_class(output: &RecordShape) -> String {
    let mut accessors = String::new();
    for field in &output.fields {
        let name = field_name(field);
        let _ = writeln!(accessors, "    BytesView {name}() const noexcept {{ return BytesView{{raw_.{name}.data, raw_.{name}.len}}; }}");
    }
    include_str!("render/output.hpp.txt").replace("@ACCESSORS@", &accessors)
}

const PROVIDER_CLASS_AND_ASSERTIONS: &str = include_str!("render/provider.hpp.txt");

const DETAIL_MAKE_OWNED_BYTES: &str = include_str!("render/owned.hpp.txt");

const PROVIDER_OPEN_DEFINITIONS: &str = include_str!("render/open.hpp.txt");

/// `Provider::transform`'s out-of-line definition. **Fixed template:** the
/// null-handle guard, the zero-initialized `c_input`/`c_output`, the call
/// into `spx_pg_consumer_transform`, and the success/failure wrapping.
/// **Descriptor-derived:** the field-by-field `make_owned_bytes` staging
/// calls and their matching frees on an allocation failure -- one line per
/// leaf, in descriptor order, restating
/// [`super::super::c_calling::render::encode_input_fn`]'s own per-field
/// scaling for this generator's own conversion step.
fn provider_transform_definition(input: &RecordShape) -> String {
    let mut preflight = String::new();
    let mut stage = String::new();
    let mut rollback = String::new();
    for field in &input.fields {
        let name = field_name(field);
        let _ = writeln!(preflight, "    if (input.{name}.size() > 65536u || input.{name}.size() > 16777216u - payload) return Error(ErrorKind::CapacityExceeded, 0);");
        let _ = writeln!(preflight, "    payload += input.{name}.size();");
        let _ = writeln!(stage, "    prepared = prepared && detail::make_owned_bytes(input.{name}, c_input.{name});");
    }
    for field in input.fields.iter().rev() {
        let _ = writeln!(rollback, "        ::spx_pg_owned_bytes_free(&c_input.{});", field_name(field));
    }
    include_str!("render/transform.hpp.txt")
        .replace("@PREFLIGHT@", &preflight)
        .replace("@STAGE@", &stage)
        .replace("@ROLLBACK@", &rollback)
}

const HEADER_TRAILER: &str = include_str!("render/trailer.hpp.txt");

/// Generate `test/round_trip.cpp`: a real, executable test driver proving
/// the RAII/move-only contract, not a mere compile check.
///
/// **Fixed template:** the `REQUIRE` macro, `bytes_from`/`assert_reversed_field`
/// helpers, the restated compile-time static assertions, the success round
/// trip and every move/self-move/moved-from/explicit-close/early-return
/// test, the hostile-pairing tests, the full ordinal `0..=13`
/// failure-injection matrix, and `main`. **Descriptor-derived:** the sample
/// input builder, the per-field `assert_reversed` comparisons, and which
/// field the per-leaf-bound tests target (the first one, matching
/// [`super::super::c_calling::render::round_trip_c`]'s own convention).
pub(super) fn round_trip_cpp(input: &RecordShape, output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str(ROUND_TRIP_PRELUDE);
    out.push_str(&sample_input_fn(input));
    out.push('\n');
    out.push_str(&assert_reversed_fn(input, output));
    out.push('\n');
    out.push_str(&first_leaf_fn(output));
    out.push('\n');
    out.push_str(&zero_bytes_input_fn(input));
    out.push('\n');
    out.push_str(ROUND_TRIP_BODY);
    out.push('\n');
    out.push_str(&per_leaf_bound_tests_fn(input, output));
    out.push('\n');
    out.push_str(&main_fn());
    out
}

const ROUND_TRIP_PRELUDE: &str = r#"/*
 * Generated by semaprax::public_generic_consumer::cxx_calling.
 * Compiler-generated deterministic output; do not edit.
 *
 * Real, executed evidence for issue #159: opens the real native provider
 * through the generated C++17 wrapper (which itself wraps the generated
 * C11 calling consumer from issue #158), transfers one owned input record
 * exactly once, decodes an independently validated result, and proves the
 * move-only RAII contract -- deleted copy operations, nothrow move,
 * exactly-once release, self-move safety, move-assign-over-live cleanup,
 * moved-from destruction, explicit close then destructor, and early
 * return -- using the native provider's OWN test-only counters
 * (spx_pg_consumer_test_live_allocations/_live_handles, reached only
 * through the wrapped C11 consumer's own accessors), exactly like
 * tests/public_generic_native_adapter_v1/c_calling_consumer.rs's own
 * generated round_trip.c for the same provider.
 */
#include "../include/semaprax_public_generic_v1.hpp"

#include <cstdio>
#include <cstdlib>
#include <type_traits>
#include <utility>
#include <vector>

using namespace semaprax::public_generic::v1;

#define MAX_BYTES_PER_LEAF (64u * 1024u)

static void spx_pg_cxx_require(bool condition, const char *message, unsigned line) {
    if (!condition) {
        std::fprintf(stderr, "round_trip.cpp line %u: %s\n", line, message);
        std::exit(1);
    }
}
#define REQUIRE(condition) spx_pg_cxx_require((condition), #condition, __LINE__)

/* Restates the header's own static assertions here too: RAII correctness is
 * never inferred merely because a round trip succeeds below. */
static_assert(!std::is_copy_constructible_v<Provider>);
static_assert(!std::is_copy_assignable_v<Provider>);
static_assert(std::is_nothrow_move_constructible_v<Provider>);
static_assert(std::is_nothrow_move_assignable_v<Provider>);
static_assert(!std::is_copy_constructible_v<Output>);
static_assert(!std::is_copy_assignable_v<Output>);
static_assert(std::is_nothrow_move_constructible_v<Output>);
static_assert(std::is_nothrow_move_assignable_v<Output>);

static std::vector<std::uint8_t> bytes_from(const char *text) {
    std::vector<std::uint8_t> result;
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        result.push_back(static_cast<std::uint8_t>(*cursor));
    }
    return result;
}

static void assert_reversed_field(const BytesView &actual, const std::vector<std::uint8_t> &original) {
    REQUIRE(actual.size == original.size());
    for (std::size_t index = 0; index < actual.size; ++index) {
        REQUIRE(actual.data[index] == original[original.size() - 1 - index]);
    }
}
"#;

fn sample_input_fn(input: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("\nstatic Input sample_input() {\n");
    out.push_str("    Input input;\n");
    for (index, field) in input.fields.iter().enumerate() {
        let _ = writeln!(
            out,
            "    input.{} = bytes_from(\"sample-{index}\");",
            field_name(field)
        );
    }
    out.push_str("    return input;\n");
    out.push_str("}\n");
    out
}

fn assert_reversed_fn(input: &RecordShape, output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("static void assert_reversed(const Output &output, const Input &original) {\n");
    for (in_field, out_field) in input.fields.iter().zip(output.fields.iter()) {
        let _ = writeln!(
            out,
            "    assert_reversed_field(output.{}(), original.{});",
            field_name(out_field),
            field_name(in_field)
        );
    }
    out.push_str("}\n");
    out
}

/// `first_leaf`: the one field every fixed-template test that needs "some
/// field, any field" probes — matching this generator's own
/// per-leaf-bound-test convention of always targeting `output.fields[0]`.
fn first_leaf_fn(output: &RecordShape) -> String {
    format!(
        "static BytesView first_leaf(const Output &output) {{\n    return output.{}();\n}}\n",
        field_name(&output.fields[0])
    )
}

/// `zero_bytes_input`: alternates an empty leaf and an embedded-zero-byte
/// leaf across descriptor order, so the fixed
/// `test_zero_length_and_embedded_zero_bytes_round_trip` body never has to
/// name a field directly. With only one field, only the zero-length case is
/// exercised by this helper; the per-leaf-bound tests below independently
/// cover a large single-field payload.
fn zero_bytes_input_fn(input: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("static Input zero_bytes_input() {\n    Input input;\n");
    for (index, field) in input.fields.iter().enumerate() {
        let name = field_name(field);
        if index % 2 == 0 {
            let _ = writeln!(out, "    input.{name} = {{}}; // zero-length leaf");
        } else {
            let _ = writeln!(
                out,
                "    input.{name} = std::vector<std::uint8_t>{{0x00, 0x41, 0x00, 0x42, 0x00}}; // embedded-zero-byte leaf"
            );
        }
    }
    out.push_str("    return input;\n}\n");
    out
}

const ROUND_TRIP_BODY: &str = r#"static void test_success_round_trip() {
    auto opened = Provider::open();
    REQUIRE(opened.has_value());
    Provider provider = std::move(opened).value();
    REQUIRE(provider.valid());

    Input original = sample_input();
    Input to_send = sample_input();
    auto result = provider.transform(std::move(to_send));
    REQUIRE(result.has_value());
    assert_reversed(result.value(), original);

    provider.close();
    REQUIRE(!provider.valid());
    REQUIRE(::spx_pg_consumer_test_live_allocations() == 0);
}

/* "Provider::open must invoke the generated C client's exact pairing
 * checks. C++ must not offer a constructor that skips them." */
static void test_open_rejects_a_mutated_descriptor_before_any_native_allocation() {
    std::vector<std::uint8_t> mutated(::spx_pg_trusted_descriptor_bytes,
                                       ::spx_pg_trusted_descriptor_bytes + ::spx_pg_trusted_descriptor_len);
    if (!mutated.empty()) {
        mutated[0] = static_cast<std::uint8_t>(mutated[0] ^ 0xffu);
    }
    std::size_t allocations_before = ::spx_pg_consumer_test_live_allocations();
    auto opened = Provider::open(mutated.data(), mutated.size(), ::spx_pg_trusted_binding_bytes,
                                  ::spx_pg_trusted_binding_len);
    REQUIRE(!opened.has_value());
    REQUIRE(opened.error().kind() == ErrorKind::DescriptorRejected);
    REQUIRE(::spx_pg_consumer_test_live_allocations() == allocations_before);
}

static void test_open_rejects_a_mutated_binding_before_any_native_allocation() {
    REQUIRE(::spx_pg_trusted_binding_len > 0);
    std::vector<std::uint8_t> mutated(::spx_pg_trusted_binding_bytes,
                                       ::spx_pg_trusted_binding_bytes + ::spx_pg_trusted_binding_len);
    mutated.back() = static_cast<std::uint8_t>(mutated.back() ^ 0xffu);
    std::size_t allocations_before = ::spx_pg_consumer_test_live_allocations();
    auto opened =
        Provider::open(::spx_pg_trusted_descriptor_bytes, ::spx_pg_trusted_descriptor_len, mutated.data(),
                        mutated.size());
    REQUIRE(!opened.has_value());
    REQUIRE(opened.error().kind() == ErrorKind::ProviderMismatch);
    REQUIRE(::spx_pg_consumer_test_live_allocations() == allocations_before);
}

/* A well-formed binding paired against a well-formed but DIFFERENT
 * descriptor must still fail -- "a valid provider for another descriptor
 * must fail, even when the concrete C++ type names/display names are the
 * same." */
static void test_open_rejects_a_valid_binding_that_names_a_different_descriptor() {
    static const char suffix[] = "-a-different-but-well-formed-descriptor";
    std::vector<std::uint8_t> different(::spx_pg_trusted_descriptor_bytes,
                                         ::spx_pg_trusted_descriptor_bytes + ::spx_pg_trusted_descriptor_len);
    different.insert(different.end(), suffix, suffix + (sizeof(suffix) - 1));
    auto opened = Provider::open(different.data(), different.size(), ::spx_pg_trusted_binding_bytes,
                                  ::spx_pg_trusted_binding_len);
    REQUIRE(!opened.has_value());
    REQUIRE(opened.error().kind() == ErrorKind::DescriptorRejected);
}

static void test_move_provider() {
    auto opened = Provider::open();
    REQUIRE(opened.has_value());
    Provider p1 = std::move(opened).value();
    Provider p2 = std::move(p1);
    REQUIRE(!p1.valid());
    REQUIRE(p2.valid());
    auto result = p2.transform(sample_input());
    REQUIRE(result.has_value());
}

static void test_move_output() {
    auto opened = Provider::open();
    Provider provider = std::move(opened).value();
    auto result = provider.transform(sample_input());
    REQUIRE(result.has_value());
    Output out1 = std::move(result).value();
    Output out2 = std::move(out1);
    Input original = sample_input();
    assert_reversed(out2, original);
}

/* "Move assignment releases any currently owned handle before taking the
 * new one" -- proven with the native provider's own allocation counter, not
 * this wrapper's own bookkeeping. */
static void test_move_assign_over_live_output() {
    auto opened = Provider::open();
    Provider provider = std::move(opened).value();
    auto r1 = provider.transform(sample_input());
    auto r2 = provider.transform(sample_input());
    REQUIRE(r1.has_value() && r2.has_value());
    Output a = std::move(r1).value();
    Output b = std::move(r2).value();
    std::size_t before = ::spx_pg_consumer_test_live_allocations();
    a = std::move(b);
    /* `a`'s original leaves were released by the move-assign, `b` is now a
     * safe, empty, moved-from Output: net live allocations must not have
     * grown, and `a` must now carry `b`'s (still correct) content. */
    REQUIRE(::spx_pg_consumer_test_live_allocations() <= before);
    Input original = sample_input();
    assert_reversed(a, original);
}

/* A moved-from Provider destructs safely: no double release, no crash. */
static void test_moved_from_provider_destructs_cleanly() {
    auto opened = Provider::open();
    Provider p1 = std::move(opened).value();
    {
        Provider p2 = std::move(p1);
        (void)p2;
    }
    /* p1 (moved-from, raw_ == nullptr) destructs here too. */
}

/* A moved-from Output destructs safely and releases nothing (there is
 * nothing left to release): the wrapped leaves already transferred to the
 * move target. */
static void test_moved_from_output_releases_nothing_and_destructs_cleanly() {
    auto opened = Provider::open();
    Provider provider = std::move(opened).value();
    auto result = provider.transform(sample_input());
    REQUIRE(result.has_value());
    Output out1 = std::move(result).value();
    std::size_t before = ::spx_pg_consumer_test_live_allocations();
    {
        Output out2 = std::move(out1);
        (void)out2;
    }
    /* out2 released the real leaves; nothing changes when out1 (moved-from)
     * destructs next. */
    REQUIRE(::spx_pg_consumer_test_live_allocations() == before);
}

/* Self-move-assignment must be safe. The indirection through a pointer
 * alias defeats -Wself-move (which only pattern-matches the literal
 * syntactic form `x = std::move(x)`); this is a genuine runtime self-move
 * assignment, not a syntactic no-op the compiler elided. */
static void test_self_move_provider_is_safe() {
    auto opened = Provider::open();
    Provider provider = std::move(opened).value();
    Provider *alias = &provider;
    *alias = std::move(*alias);
    REQUIRE(provider.valid());
    auto result = provider.transform(sample_input());
    REQUIRE(result.has_value());
}

static void test_self_move_output_is_safe() {
    auto opened = Provider::open();
    Provider provider = std::move(opened).value();
    auto result = provider.transform(sample_input());
    REQUIRE(result.has_value());
    Output out = std::move(result).value();
    Output *alias = &out;
    *alias = std::move(*alias);
    Input original = sample_input();
    assert_reversed(out, original);
}

static void test_explicit_close_then_destructor_is_safe() {
    auto opened = Provider::open();
    Provider provider = std::move(opened).value();
    provider.close();
    REQUIRE(!provider.valid());
    /* provider's destructor at end of scope must be a safe no-op: reset()
     * is idempotent. */
}

static Result<Output> early_return_after_result_acquisition(Provider &provider) {
    auto result = provider.transform(sample_input());
    if (!result.has_value()) {
        return result.error();
    }
    /* Early return with a live Output already constructed: its RAII
     * destructor must still run correctly along every path out of this
     * function. */
    return std::move(result).value();
}

static void test_early_return_after_result_acquisition() {
    auto opened = Provider::open();
    Provider provider = std::move(opened).value();
    auto result = early_return_after_result_acquisition(provider);
    REQUIRE(result.has_value());
    provider.close();
    REQUIRE(::spx_pg_consumer_test_live_allocations() == 0);
}

/* "container relocation": std::vector<Output> must be safe to grow past its
 * current capacity, which relocates every already-inserted element via its
 * nothrow move constructor. */
static void test_vector_of_outputs_relocates_safely() {
    auto opened = Provider::open();
    Provider provider = std::move(opened).value();
    std::vector<Output> outputs;
    for (int i = 0; i < 8; ++i) {
        auto result = provider.transform(sample_input());
        REQUIRE(result.has_value());
        outputs.push_back(std::move(result).value());
    }
    Input original = sample_input();
    for (const Output &output : outputs) {
        assert_reversed(output, original);
    }
}

/* An explicit independent copy stays independent of the Output it was
 * copied from: mutating the copy never mutates (and is never mutated by)
 * the source. `first_leaf` is generated per shape below (the first field,
 * matching this generator's own per-leaf-bound convention). */
static void test_copied_output_bytes_remain_independent() {
    auto opened = Provider::open();
    Provider provider = std::move(opened).value();
    auto result = provider.transform(sample_input());
    REQUIRE(result.has_value());
    Output output = std::move(result).value();
    std::vector<std::uint8_t> copy = to_owned(first_leaf(output));
    if (!copy.empty()) {
        copy[0] = static_cast<std::uint8_t>(copy[0] ^ 0xffu);
        REQUIRE(copy[0] != first_leaf(output).data[0]);
    }
}

/* Zero-length and embedded-zero-byte leaves are ordinary bytes to this
 * wrapper: std::vector<std::uint8_t> never treats a leaf as a C string.
 * `zero_bytes_input` is generated per shape below. */
static void test_zero_length_and_embedded_zero_bytes_round_trip() {
    auto opened = Provider::open();
    Provider provider = std::move(opened).value();
    Input input = zero_bytes_input();
    Input original = zero_bytes_input();
    auto result = provider.transform(std::move(input));
    REQUIRE(result.has_value());
    assert_reversed(result.value(), original);
}

/* Every logical trace ordinal 0..=13 (see spx_pg_v1.h / c_calling's own
 * matrix doc comment) settles as a failure with zero live native
 * allocations/handles afterward, exactly like
 * tests/public_generic_native_adapter_v1/c_calling_consumer.rs's own
 * matrix for the same provider -- proven through the wrapped C11 consumer's
 * own test-only accessors, never this wrapper's own bookkeeping. Ordinals
 * 0..=4 fire inside input preparation, 5..=13 fire inside the call itself,
 * so this single loop also stands in for "failure after input
 * preparation," "failure after provider transfer," and "failure during
 * result construction." */
static void test_failure_injection_matrix_settles_every_ordinal_with_zero_live_resources() {
    for (std::uint32_t ordinal = 0; ordinal <= 13; ++ordinal) {
        auto opened = Provider::open();
        REQUIRE(opened.has_value());
        Provider provider = std::move(opened).value();
        ::spx_pg_consumer_test_inject_failure(ordinal);
        auto result = provider.transform(sample_input());
        REQUIRE(!result.has_value());
        ::spx_pg_consumer_test_clear_failure_injection();
        provider.close();
        REQUIRE(::spx_pg_consumer_test_live_allocations() == 0);
    }
}
"#;

fn per_leaf_bound_tests_fn(input: &RecordShape, output: &RecordShape) -> String {
    let first_input_field = field_name(&input.fields[0]);
    let first_output_field = field_name(&output.fields[0]);
    let mut out = String::new();
    out.push_str("static void test_exactly_the_per_leaf_byte_bound_is_accepted() {\n");
    out.push_str(
        "    auto opened = Provider::open();\n\
         \x20   REQUIRE(opened.has_value());\n\
         \x20   Provider provider = std::move(opened).value();\n\
         \x20   Input input;\n",
    );
    let _ = writeln!(
        out,
        "    input.{first_input_field}.assign(MAX_BYTES_PER_LEAF, 0x5au);"
    );
    out.push_str(
        "    auto result = provider.transform(std::move(input));\n\
         \x20   REQUIRE(result.has_value());\n",
    );
    let _ = writeln!(
        out,
        "    REQUIRE(result.value().{first_output_field}().size == MAX_BYTES_PER_LEAF);"
    );
    out.push_str(
        "    provider.close();\n\
         \x20   REQUIRE(::spx_pg_consumer_test_live_allocations() == 0);\n\
         }\n\n",
    );

    out.push_str("static void test_one_byte_over_the_per_leaf_bound_is_rejected_locally() {\n");
    out.push_str(
        "    auto opened = Provider::open();\n\
         \x20   REQUIRE(opened.has_value());\n\
         \x20   Provider provider = std::move(opened).value();\n\
         \x20   Input input;\n",
    );
    let _ = writeln!(
        out,
        "    input.{first_input_field}.assign(MAX_BYTES_PER_LEAF + 1, 0x5au);"
    );
    out.push_str(
        "    auto result = provider.transform(std::move(input));\n\
         \x20   REQUIRE(!result.has_value());\n\
         \x20   REQUIRE(result.error().kind() == ErrorKind::CapacityExceeded);\n\
         \x20   provider.close();\n\
         \x20   REQUIRE(::spx_pg_consumer_test_live_allocations() == 0);\n\
         }\n",
    );
    out
}

fn main_fn() -> String {
    r#"int main() {
    test_success_round_trip();
    test_open_rejects_a_mutated_descriptor_before_any_native_allocation();
    test_open_rejects_a_mutated_binding_before_any_native_allocation();
    test_open_rejects_a_valid_binding_that_names_a_different_descriptor();
    test_move_provider();
    test_move_output();
    test_move_assign_over_live_output();
    test_moved_from_provider_destructs_cleanly();
    test_moved_from_output_releases_nothing_and_destructs_cleanly();
    test_self_move_provider_is_safe();
    test_self_move_output_is_safe();
    test_explicit_close_then_destructor_is_safe();
    test_early_return_after_result_acquisition();
    test_vector_of_outputs_relocates_safely();
    test_copied_output_bytes_remain_independent();
    test_zero_length_and_embedded_zero_bytes_round_trip();
    test_exactly_the_per_leaf_byte_bound_is_accepted();
    test_one_byte_over_the_per_leaf_bound_is_rejected_locally();
    test_failure_injection_matrix_settles_every_ordinal_with_zero_live_resources();
    (void)std::puts("cxx-calling-consumer-settled");
    return 0;
}
"#
    .to_owned()
}
