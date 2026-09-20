//! Mutation proof for the generated native result-carrier codec. This is a
//! sibling of the shared cross-language corpus rather than an extra top-level
//! integration binary, preserving the native-adapter harness's one-binary
//! linking boundary.

use std::fs;
use std::process::Command;

use semaprax::public_generic_consumer::c_calling::generate_c_calling_consumer;
use semaprax::public_generic_consumer::cxx_calling::generate_cxx_calling_consumer;

use super::shared_hostile_corpus::{
    c_byte_array_literal, compile_provider_object, fixture_binding, replace_once, run, shapes,
    splice_main_call, tool, write_generated_files, Workspace,
};

#[path = "../support/public_generic_hostile_corpus.rs"]
mod public_generic_hostile_corpus;
use public_generic_hostile_corpus::{
    baseline_descriptor_bytes, malformed_result_carrier_cases, EXPECTED,
};

struct Mutation {
    label: &'static str,
    case: &'static str,
    old: &'static str,
    new: &'static str,
}

fn hostile_bytes(case: &str) -> Vec<u8> {
    malformed_result_carrier_cases()
        .into_iter()
        .find(|(name, _)| *name == case)
        .map(|(_, bytes)| bytes)
        .unwrap_or_else(|| panic!("the closed result-carrier corpus is missing `{case}`"))
}

fn expected_status(case: &str) -> &'static str {
    EXPECTED
        .iter()
        .find(|(name, _)| *name == case)
        .map(|(_, status)| *status)
        .unwrap_or_else(|| panic!("the closed shared manifest is missing `{case}`"))
}

fn c_probe(bytes: &[u8], marker: &str) -> String {
    format!(
        r#"static void test_mutated_result_carrier_guard(void) {{
    static const uint8_t candidate[] = {};
    size_t before = spx_pg_consumer_test_live_allocations();
    REQUIRE(spx_pg_consumer_test_validate_result_carrier(candidate, sizeof(candidate)) ==
            SPX_PG_CONSUMER_OK);
    REQUIRE(spx_pg_consumer_test_live_allocations() == before);
    (void)puts("{marker}");
}}
"#,
        c_byte_array_literal(bytes)
    )
}

fn cxx_probe(bytes: &[u8], marker: &str) -> String {
    format!(
        r#"static void test_mutated_result_carrier_guard() {{
    const std::vector<std::uint8_t> candidate {};
    const std::size_t before = ::spx_pg_consumer_test_live_allocations();
    REQUIRE(::spx_pg_consumer_test_validate_result_carrier(candidate.data(), candidate.size()) ==
            SPX_PG_CONSUMER_OK);
    REQUIRE(::spx_pg_consumer_test_live_allocations() == before);
    std::puts("{marker}");
}}
"#,
        c_byte_array_literal(bytes)
    )
}

/// The complete native hostile matrix needs independently discriminating
/// documents for three distinct decoder checks: exact leaf count, per-leaf
/// capacity (in the shared-corpus sibling), and no trailing bytes. This test
/// covers the first and third in C11 and the documented C++17 facade. Every
/// mutant is built from a fresh generated artifact; no generator source or
/// checked-in consumer is edited.
#[test]
fn result_carrier_count_and_trailing_guards_are_detected_by_native_consumers() {
    let clang = tool("CLANG", "clang");
    let clangxx = tool("CLANGXX", "clang++");
    let (input, output) = shapes();
    let binding = fixture_binding();
    let workspace = Workspace::new("result-carrier-framing-mutants");
    let provider_object =
        compile_provider_object(&workspace.0, baseline_descriptor_bytes(), &binding, &clang);
    let mutations = [
        Mutation {
            label: "leaf-count",
            case: "result_carrier_wrong_leaf_count",
            old: "if (spx_pg_ccc_read_u64le(bytes) != (uint64_t)FIELD_COUNT) return SPX_PG_CONSUMER_RESULT_REJECTED;",
            new: "if (spx_pg_ccc_read_u64le(bytes) != (uint64_t)FIELD_COUNT) return SPX_PG_CONSUMER_OK;",
        },
        Mutation {
            label: "trailing-byte",
            case: "result_carrier_trailing_byte",
            old: "if (offset != len) return SPX_PG_CONSUMER_RESULT_REJECTED;",
            new: "if (offset != len) return SPX_PG_CONSUMER_OK;",
        },
    ];

    for mutation in mutations {
        assert_eq!(
            expected_status(mutation.case),
            "RESULT_REJECTED",
            "the normal corpus must reject the document this `{}` mutant admits",
            mutation.label
        );
        let bytes = hostile_bytes(mutation.case);
        let marker = format!("MUTATED_RESULT_CARRIER_{}_GUARD_ADMITTED", mutation.label);

        // C11's generated consumer owns the real codec implementation.
        let c_consumer =
            generate_c_calling_consumer(baseline_descriptor_bytes(), &binding, &input, &output)
                .expect("a well-formed shape must generate");
        let c_root = workspace.path(&format!("c-{}", mutation.label));
        write_generated_files(&c_root, c_consumer.files(), None);
        let c_codec_path = c_root.join("spx_pg_calling_consumer.c");
        let mut c_codec = fs::read_to_string(&c_codec_path).unwrap();
        replace_once(&mut c_codec, mutation.old, mutation.new, mutation.label);
        fs::write(&c_codec_path, c_codec).unwrap();
        let c_round_trip_path = c_root.join("round_trip.c");
        let mut c_round_trip = fs::read_to_string(&c_round_trip_path).unwrap();
        splice_main_call(
            &mut c_round_trip,
            "int main(void) {",
            &c_probe(&bytes, &marker),
        );
        splice_main_call(
            &mut c_round_trip,
            "(void)puts(\"c-calling-consumer-settled\");",
            "test_mutated_result_carrier_guard();\n    ",
        );
        fs::write(&c_round_trip_path, c_round_trip).unwrap();
        let c_executable = c_root.join("result_carrier_mutant");
        let c_built = run(
            Command::new(&clang)
                .current_dir(&c_root)
                .args(["-std=c11", "-O0", "-Wall", "-Wextra", "-Werror"])
                .arg("spx_pg_calling_consumer.c")
                .arg("round_trip.c")
                .arg(&provider_object)
                .arg("-o")
                .arg(&c_executable),
            "compile the C11 result-carrier framing mutant",
        );
        assert!(
            c_built.status.success(),
            "{}: {}",
            mutation.label,
            String::from_utf8_lossy(&c_built.stderr)
        );
        let c_run = run(
            Command::new(&c_executable).current_dir(&c_root),
            "run the C11 result-carrier framing mutant",
        );
        assert!(
            c_run.status.success() && String::from_utf8_lossy(&c_run.stdout).contains(&marker),
            "{} C11 mutation was not detected:\nstdout:\n{}\nstderr:\n{}",
            mutation.label,
            String::from_utf8_lossy(&c_run.stdout),
            String::from_utf8_lossy(&c_run.stderr)
        );

        // C++17 has no second codec: it must exercise the C11 mutant through
        // the generated facade, which is the boundary its contract promises.
        let cxx_consumer =
            generate_cxx_calling_consumer(baseline_descriptor_bytes(), &binding, &input, &output)
                .expect("a well-formed shape must generate");
        let cxx_root = workspace.path(&format!("cxx-{}", mutation.label));
        write_generated_files(&cxx_root, cxx_consumer.files(), None);
        let cxx_codec_path = cxx_root.join("spx_pg_calling_consumer.c");
        let mut cxx_codec = fs::read_to_string(&cxx_codec_path).unwrap();
        replace_once(&mut cxx_codec, mutation.old, mutation.new, mutation.label);
        fs::write(&cxx_codec_path, cxx_codec).unwrap();
        let cxx_round_trip_path = cxx_root.join("test/round_trip.cpp");
        let mut cxx_round_trip = fs::read_to_string(&cxx_round_trip_path).unwrap();
        splice_main_call(
            &mut cxx_round_trip,
            "int main() {",
            &cxx_probe(&bytes, &marker),
        );
        splice_main_call(
            &mut cxx_round_trip,
            "std::puts(\"cxx-calling-consumer-settled\");",
            "test_mutated_result_carrier_guard();\n    ",
        );
        fs::write(&cxx_round_trip_path, cxx_round_trip).unwrap();
        let cxx_consumer_object = cxx_root.join("spx_pg_calling_consumer.o");
        let cxx_c_built = run(
            Command::new(&clang)
                .current_dir(&cxx_root)
                .args(["-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-c"])
                .arg("spx_pg_calling_consumer.c")
                .arg("-o")
                .arg(&cxx_consumer_object),
            "compile the C++17 facade's C11 result-carrier framing mutant",
        );
        assert!(
            cxx_c_built.status.success(),
            "{}: {}",
            mutation.label,
            String::from_utf8_lossy(&cxx_c_built.stderr)
        );
        let cxx_executable = cxx_root.join("result_carrier_mutant");
        let cxx_built = run(
            Command::new(&clangxx)
                .current_dir(&cxx_root)
                .args([
                    "-std=c++17",
                    "-O0",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Iinclude",
                    "-I.",
                ])
                .arg("test/round_trip.cpp")
                .arg(&cxx_consumer_object)
                .arg(&provider_object)
                .arg("-o")
                .arg(&cxx_executable),
            "compile the C++17 result-carrier framing mutant",
        );
        assert!(
            cxx_built.status.success(),
            "{}: {}",
            mutation.label,
            String::from_utf8_lossy(&cxx_built.stderr)
        );
        let cxx_run = run(
            Command::new(&cxx_executable).current_dir(&cxx_root),
            "run the C++17 result-carrier framing mutant",
        );
        assert!(
            cxx_run.status.success() && String::from_utf8_lossy(&cxx_run.stdout).contains(&marker),
            "{} C++17 mutation was not detected:\nstdout:\n{}\nstderr:\n{}",
            mutation.label,
            String::from_utf8_lossy(&cxx_run.stdout),
            String::from_utf8_lossy(&cxx_run.stderr)
        );
    }
}
