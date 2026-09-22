//! Runtime regression for #173: byte identity alone cannot authorize a
//! calling consumer.  The generated package deliberately embeds a truncated
//! descriptor and the caller submits those exact embedded bytes.  The native
//! provider would accept that byte-exact pair, so the generated consumer must
//! reject the descriptor envelope itself before it can allocate or call it.
//!
//! The original regression pinned one malformed shape (a truncated final
//! frame).  `malformed_trusted_corpus_is_refused_by_the_c11_and_cxx17_consumers`
//! and `..._by_the_rust_consumer` below extend that to the whole closed
//! manifest in
//! `tests/support/public_generic_hostile_corpus.rs::malformed_trusted_descriptor_cases`,
//! so every branch of the generated consumers' bounded Descriptor-v1
//! envelope check — not only "a frame runs off the end" — is driven by a
//! case whose byte-exact pairing check cannot refuse it.  That manifest's
//! module documentation explains why this family, and not
//! `structured_descriptor_cases`, is the one that discriminates a real
//! envelope check from a deleted one.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::public_generic_abi::carrier::{CarrierBindingV1, TargetProfile};
use semaprax::public_generic_abi::descriptor::{DescriptorV1, InstanceBinding};
use semaprax::public_generic_abi::native::binding::NativeProviderBindingV1;
use semaprax::public_generic_abi::native::template::render_reference_provider;
use semaprax::public_generic_consumer::c_calling::generate_c_calling_consumer;
use semaprax::public_generic_consumer::cxx_calling::generate_cxx_calling_consumer;
use semaprax::public_generic_consumer::rust_calling::{
    generate_rust_calling_consumer, OwnedByteField, RecordShape,
};

use crate::public_generic_hostile_corpus::{
    malformed_trusted_descriptor_cases, malformed_trusted_descriptor_mutation_cases,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Workspace(PathBuf);

impl Workspace {
    fn new(label: &str) -> Self {
        let root = env::temp_dir().join(format!(
            "spx-pg-malformed-trusted-descriptor-{}-{}-{label}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tool(variable: &str, fallback: &str) -> PathBuf {
    env::var_os(variable).map_or_else(|| PathBuf::from(fallback), PathBuf::from)
}

fn malformed_descriptor() -> Vec<u8> {
    let mut bytes =
        DescriptorV1::new(
            "sample.transform",
            "transform",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            InstanceBinding {
                term: "@11:sample.pair<bytes,bool>".to_owned(),
                instance_digest:
                    "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                        .to_owned(),
            },
            InstanceBinding {
                term: "@11:sample.pair<bytes,i64>".to_owned(),
                instance_digest:
                    "sha256:5555555555555555555555555555555555555555555555555555555555555555"
                        .to_owned(),
            },
        )
        .encode();
    bytes
        .pop()
        .expect("canonical descriptor has a trailing byte");
    bytes
}

fn binding() -> NativeProviderBindingV1 {
    NativeProviderBindingV1::new(
        CarrierBindingV1::new(
            "sha256:6666666666666666666666666666666666666666666666666666666666666666",
            TargetProfile::NativeC11,
            "runtime:native-c11-malformed-trusted-descriptor",
        ),
        "sha256:7777777777777777777777777777777777777777777777777777777777777777",
        "spx_pg_endpoint_reverse_bytes_v1",
        "semaprax-0.4.1",
    )
}

fn shapes() -> (RecordShape, RecordShape) {
    let input = RecordShape::new(vec![OwnedByteField::new("malformed.input")]);
    (input.clone(), input)
}

fn write_files(root: &Path, files: &[(String, String)]) {
    for (relative, contents) in files {
        let destination = root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(destination, contents).unwrap();
    }
}

fn run(command: &mut Command, label: &str) {
    let result = command
        .output()
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    assert!(
        result.status.success(),
        "{label} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        result.stderr.is_empty(),
        "{label} emitted warnings:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn run_cargo(command: &mut Command, label: &str) {
    let result = command
        .output()
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    assert!(
        result.status.success(),
        "{label} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

fn compile_provider(root: &Path, bytes: &[u8], binding: &NativeProviderBindingV1) -> PathBuf {
    let clang = tool("CLANG", "clang");
    let source = root.join("provider.c");
    let object = root.join("provider.o");
    fs::write(&source, render_reference_provider(bytes, binding)).unwrap();
    run(
        Command::new(clang)
            .current_dir(root)
            .args(["-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-c"])
            .arg(&source)
            .arg("-o")
            .arg(&object),
        "compile reference provider",
    );
    object
}

const C_DRIVER: &str = r#"#include "spx_pg_calling_consumer.h"
int main(void) {
    spx_pg_calling_consumer *consumer = (spx_pg_calling_consumer *)(void *)0x1;
    if (spx_pg_consumer_open(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len,
                             spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len,
                             &consumer) != SPX_PG_CONSUMER_DESCRIPTOR_REJECTED) return 1;
    if (consumer != 0) return 2;
    return spx_pg_consumer_test_live_allocations() == 0 ? 0 : 3;
}
"#;

const CXX_DRIVER: &str = r#"#include "include/semaprax_public_generic_v1.hpp"
int main() {
    auto opened = semaprax::public_generic::v1::Provider::open();
    if (opened.has_value()) return 1;
    if (opened.error().kind() != semaprax::public_generic::v1::ErrorKind::DescriptorRejected) return 2;
    return spx_pg_consumer_test_live_allocations() == 0 ? 0 : 3;
}
"#;

/// A deliberately weakened consumer must reach the provider.  The reference
/// provider is configured with the same bytes, so this proves the consumer's
/// own envelope check -- rather than byte pairing or provider replay -- is
/// what made the canonical driver refuse before allocation.
const C_MUTANT_DRIVER: &str = r#"#include "spx_pg_calling_consumer.h"
int main(void) {
    size_t allocations_before = spx_pg_consumer_test_live_allocations();
    spx_pg_calling_consumer *consumer = NULL;
    if (spx_pg_consumer_open(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len,
                             spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len,
                             &consumer) != SPX_PG_CONSUMER_OK || consumer == NULL) return 1;
    if (spx_pg_consumer_test_live_allocations() <= allocations_before) return 2;
    if (spx_pg_consumer_close_checked(&consumer, NULL) != SPX_PG_CONSUMER_OK || consumer != NULL) return 3;
    return spx_pg_consumer_test_live_allocations() == allocations_before ? 0 : 4;
}
"#;

const CXX_MUTANT_DRIVER: &str = r#"#include "include/semaprax_public_generic_v1.hpp"
int main() {
    const auto before = spx_pg_consumer_test_live_allocations();
    {
        auto opened = semaprax::public_generic::v1::Provider::open();
        if (!opened.has_value()) return 1;
        if (spx_pg_consumer_test_live_allocations() <= before) return 2;
    }
    return spx_pg_consumer_test_live_allocations() == before ? 0 : 3;
}
"#;

fn replace_once(source: &mut String, old: &str, new: &str, label: &str) {
    assert_eq!(
        source.matches(old).count(),
        1,
        "{label}: generated-source mutation anchor drifted: {old:?}"
    );
    *source = source.replacen(old, new, 1);
}

/// Mutate precisely one C11 descriptor-envelope refusal branch.  The C++17
/// wrapper delegates to this same generated C11 implementation. Both native
/// language facades execute each weakened branch below.
fn weaken_c11_descriptor_branch(source: &mut String, case: &str) {
    match case {
        "truncated_final_frame" => replace_once(
            source,
            "if (width > length - offset) return 0;",
            "if (width > length - offset) { offset = length; break; }",
            case,
        ),
        "unknown_descriptor_schema" => replace_once(
            source,
            "if (field == 0u) { version = descriptor_schema; version_length = sizeof(descriptor_schema) - 1u; }",
            "if (field == 13u) { version = descriptor_schema; version_length = sizeof(descriptor_schema) - 1u; }",
            case,
        ),
        "stale_boundary_profile_version" => replace_once(
            source,
            "if (field == 1u) { version = boundary_schema; version_length = sizeof(boundary_schema) - 1u; }",
            "if (field == 13u) { version = boundary_schema; version_length = sizeof(boundary_schema) - 1u; }",
            case,
        ),
        "stale_type_grammar_version" => replace_once(
            source,
            "if (field == 2u) { version = grammar_schema; version_length = sizeof(grammar_schema) - 1u; }",
            "if (field == 13u) { version = grammar_schema; version_length = sizeof(grammar_schema) - 1u; }",
            case,
        ),
        "invalid_utf8_export_id" => replace_once(
            source,
            "if (!spx_pg_ccc_utf8(content, field_length)) return 0;",
            "if (!spx_pg_ccc_utf8(content, field_length) && field == 13u) return 0;",
            case,
        ),
        "trailing_bytes_after_final_frame" => {
            replace_once(source, "return offset == length;", "return 1;", case)
        }
        other => panic!("{other}: not an admitted #173 mutation control"),
    }
}

fn weaken_rust_descriptor_branch(source: &mut String, case: &str) {
    match case {
        "truncated_final_frame" => replace_once(
            source,
            "if end > bytes.len() { return None; }",
            "if end > bytes.len() { offset = bytes.len(); break; }",
            case,
        ),
        "unknown_descriptor_schema" => replace_once(
            source,
            "0 => Some(b\"semaprax.public-generic-descriptor.v1\".as_slice()),",
            "13 => Some(b\"semaprax.public-generic-descriptor.v1\".as_slice()),",
            case,
        ),
        "stale_boundary_profile_version" => replace_once(
            source,
            "1 => Some(b\"semaprax.public-generic-boundary-profile.v1\".as_slice()),",
            "13 => Some(b\"semaprax.public-generic-boundary-profile.v1\".as_slice()),",
            case,
        ),
        "stale_type_grammar_version" => replace_once(
            source,
            "2 => Some(b\"semaprax.public-generic-type-grammar.v1\".as_slice()),",
            "13 => Some(b\"semaprax.public-generic-type-grammar.v1\".as_slice()),",
            case,
        ),
        "invalid_utf8_export_id" => replace_once(
            source,
            "if std::str::from_utf8(content).is_err() { return None; }",
            "if false { return None; }",
            case,
        ),
        "trailing_bytes_after_final_frame" => replace_once(
            source,
            "(offset == bytes.len()).then_some(fields)",
            "Some(fields)",
            case,
        ),
        other => panic!("{other}: not an admitted #173 mutation control"),
    }
}

/// Generate, build and run the C11 and C++17 calling consumers configured
/// with `bytes` as their trusted descriptor, and require each to refuse
/// those same bytes with `DESCRIPTOR_REJECTED`, leaving no live allocation
/// and no opened consumer handle (the drivers above assert both).
fn assert_c11_and_cxx17_consumers_reject(
    label: &str,
    bytes: &[u8],
    binding: &NativeProviderBindingV1,
) {
    let (input, output) = shapes();
    let workspace = Workspace::new(label);
    let provider = compile_provider(&workspace.0, bytes, binding);
    let clang = tool("CLANG", "clang");

    let c = generate_c_calling_consumer(bytes, binding, &input, &output)
        .expect("generation keeps its byte-oriented API for this regression");
    let c_root = workspace.0.join("c");
    fs::create_dir_all(&c_root).unwrap();
    write_files(&c_root, c.files());
    fs::write(c_root.join("malformed.c"), C_DRIVER).unwrap();
    let c_binary = c_root.join(format!("malformed{}", env::consts::EXE_SUFFIX));
    run(
        Command::new(&clang)
            .current_dir(&c_root)
            .args(["-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-I."])
            .args(["spx_pg_calling_consumer.c", "malformed.c"])
            .arg(&provider)
            .arg("-o")
            .arg(&c_binary),
        &format!("[{label}] build C11 malformed-descriptor driver"),
    );
    run(
        Command::new(&c_binary).current_dir(&c_root),
        &format!("[{label}] run C11 malformed-descriptor driver"),
    );

    let cxx = generate_cxx_calling_consumer(bytes, binding, &input, &output)
        .expect("generation keeps its byte-oriented API for this regression");
    let cxx_root = workspace.0.join("cxx");
    fs::create_dir_all(&cxx_root).unwrap();
    write_files(&cxx_root, cxx.files());
    fs::write(cxx_root.join("malformed.cpp"), CXX_DRIVER).unwrap();
    let c_consumer = cxx_root.join("consumer.o");
    run(
        Command::new(&clang)
            .current_dir(&cxx_root)
            .args(["-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-c"])
            .arg("spx_pg_calling_consumer.c")
            .arg("-o")
            .arg(&c_consumer),
        &format!("[{label}] compile C11 consumer for C++17 driver"),
    );
    let cxx_binary = cxx_root.join(format!("malformed{}", env::consts::EXE_SUFFIX));
    run(
        Command::new(tool("CLANGXX", "clang++"))
            .current_dir(&cxx_root)
            .args([
                "-std=c++17",
                "-O1",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I.",
                "-Iinclude",
            ])
            .arg("malformed.cpp")
            .arg(&c_consumer)
            .arg(&provider)
            .arg("-o")
            .arg(&cxx_binary),
        &format!("[{label}] build C++17 malformed-descriptor driver"),
    );
    run(
        Command::new(&cxx_binary).current_dir(&cxx_root),
        &format!("[{label}] run C++17 malformed-descriptor driver"),
    );
}

/// Execute one deliberately weakened generated C11 consumer.  Success here is
/// the negative-control result: it proves that removing this exact envelope
/// refusal lets its byte-identical malformed trusted descriptor open.
fn assert_c11_mutation_is_detected(label: &str, bytes: &[u8], binding: &NativeProviderBindingV1) {
    let (input, output) = shapes();
    let workspace = Workspace::new(&format!("mutant-{label}"));
    let provider = compile_provider(&workspace.0, bytes, binding);
    let consumer = generate_c_calling_consumer(bytes, binding, &input, &output)
        .expect("generation keeps its byte-oriented API for this regression");
    let root = workspace.0.join("c");
    fs::create_dir_all(&root).unwrap();
    write_files(&root, consumer.files());
    let source_path = root.join("spx_pg_calling_consumer.c");
    let mut source = fs::read_to_string(&source_path).unwrap();
    weaken_c11_descriptor_branch(&mut source, label);
    fs::write(&source_path, &source).unwrap();
    fs::write(root.join("mutant.c"), C_MUTANT_DRIVER).unwrap();
    let binary = root.join(format!("mutant{}", env::consts::EXE_SUFFIX));
    run(
        Command::new(tool("CLANG", "clang"))
            .current_dir(&root)
            .args(["-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-I."])
            .args(["spx_pg_calling_consumer.c", "mutant.c"])
            .arg(&provider)
            .arg("-o")
            .arg(&binary),
        &format!("[{label}] build C11 descriptor-envelope mutant"),
    );
    run(
        Command::new(&binary).current_dir(&root),
        &format!("[{label}] run C11 descriptor-envelope mutant"),
    );

    // Execute the generated C++ facade too: sharing its C decoder does not
    // prove the C++ wrapper has no independent masking refusal.
    let cxx = generate_cxx_calling_consumer(bytes, binding, &input, &output).unwrap();
    let cxx_root = workspace.0.join("cxx");
    write_files(&cxx_root, cxx.files());
    let cxx_source_path = cxx_root.join("spx_pg_calling_consumer.c");
    let mut cxx_source = fs::read_to_string(&cxx_source_path).unwrap();
    weaken_c11_descriptor_branch(&mut cxx_source, label);
    assert_eq!(
        source, cxx_source,
        "{label}: C and C++ must exercise the same decoder"
    );
    fs::write(&cxx_source_path, cxx_source).unwrap();
    fs::write(cxx_root.join("mutant.cpp"), CXX_MUTANT_DRIVER).unwrap();
    let c_object = cxx_root.join("consumer.o");
    run(
        Command::new(tool("CLANG", "clang"))
            .current_dir(&cxx_root)
            .args(["-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-c"])
            .arg("spx_pg_calling_consumer.c")
            .arg("-o")
            .arg(&c_object),
        &format!("[{label}] compile C++ descriptor-envelope decoder mutant"),
    );
    let cxx_binary = cxx_root.join(format!("mutant{}", env::consts::EXE_SUFFIX));
    run(
        Command::new(tool("CLANGXX", "clang++"))
            .current_dir(&cxx_root)
            .args([
                "-std=c++17",
                "-O1",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I.",
                "-Iinclude",
            ])
            .arg("mutant.cpp")
            .arg(&c_object)
            .arg(&provider)
            .arg("-o")
            .arg(&cxx_binary),
        &format!("[{label}] build C++17 descriptor-envelope mutant"),
    );
    run(
        Command::new(&cxx_binary).current_dir(&cxx_root),
        &format!("[{label}] run C++17 descriptor-envelope mutant"),
    );
}

/// The Rust half of [`assert_c11_and_cxx17_consumers_reject`]: the generated
/// crate's own test asserts `Error::DescriptorRejected` and an unchanged
/// live-allocation count, so a refusal that happened after allocation would
/// fail.
fn assert_rust_consumer_rejects(label: &str, bytes: &[u8], binding: &NativeProviderBindingV1) {
    let (input, output) = shapes();
    let consumer = generate_rust_calling_consumer(bytes, binding, &input, &output)
        .expect("generation keeps its byte-oriented API for this regression");
    let workspace = Workspace::new(label);
    let provider = compile_provider(&workspace.0, bytes, binding);
    let lib_dir = workspace.0.join("provider-lib");
    fs::create_dir_all(&lib_dir).unwrap();
    let archive = lib_dir.join("libspx_pg_reference_provider.a");
    run(
        Command::new(tool("AR", "ar"))
            .args(["rcs"])
            .arg(&archive)
            .arg(&provider),
        "archive reference provider",
    );
    let crate_root = workspace.0.join("consumer");
    write_files(&crate_root, consumer.files());
    fs::write(
        crate_root.join("tests/round_trip.rs"),
        r#"use spx_pg_rust_calling_consumer::{diagnostics, Error, Provider, TRUSTED_BINDING_BYTES, TRUSTED_DESCRIPTOR_BYTES};
#[test]
fn exact_malformed_trusted_bytes_are_rejected_before_provider_allocation() {
    let before = diagnostics::live_allocations();
    let error = match Provider::open(TRUSTED_DESCRIPTOR_BYTES, TRUSTED_BINDING_BYTES) {
        Ok(_) => panic!("the malformed trusted descriptor must not open"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::DescriptorRejected(_)));
    assert_eq!(diagnostics::live_allocations(), before);
}
"#,
    )
    .unwrap();
    let target = workspace.0.join("cargo-target");
    let mut cargo = Command::new(tool("CARGO", "cargo"));
    cargo
        .current_dir(&crate_root)
        .env("CARGO_TARGET_DIR", &target)
        .env("SPX_PG_PROVIDER_LIB_DIR", &lib_dir)
        .env("SPX_PG_PROVIDER_LIB_NAME", "spx_pg_reference_provider")
        .env_remove("RUSTC_WRAPPER")
        .args(["test", "--", "--test-threads=1"]);
    run_cargo(
        &mut cargo,
        &format!("[{label}] run Rust malformed-descriptor driver"),
    );
}

/// Rust counterpart of [`assert_c11_mutation_is_detected`].  It modifies only
/// the temporary generated crate, compiles it, and requires `Provider::open`
/// to reach the configured reference provider.  Thus the test fails if a
/// mutation anchor drifts or if the supposedly independent branch is masked
/// by pairing or by the provider.
fn assert_rust_mutation_is_detected(label: &str, bytes: &[u8], binding: &NativeProviderBindingV1) {
    let (input, output) = shapes();
    let consumer = generate_rust_calling_consumer(bytes, binding, &input, &output)
        .expect("generation keeps its byte-oriented API for this regression");
    let workspace = Workspace::new(&format!("mutant-{label}"));
    let provider = compile_provider(&workspace.0, bytes, binding);
    let lib_dir = workspace.0.join("provider-lib");
    fs::create_dir_all(&lib_dir).unwrap();
    let archive = lib_dir.join("libspx_pg_reference_provider.a");
    run(
        Command::new(tool("AR", "ar"))
            .args(["rcs"])
            .arg(&archive)
            .arg(&provider),
        "archive reference provider for descriptor-envelope mutant",
    );
    let crate_root = workspace.0.join("consumer");
    write_files(&crate_root, consumer.files());
    let descriptor_path = crate_root.join("src/descriptor.rs");
    let mut descriptor = fs::read_to_string(&descriptor_path).unwrap();
    weaken_rust_descriptor_branch(&mut descriptor, label);
    fs::write(&descriptor_path, descriptor).unwrap();
    fs::write(
        crate_root.join("tests/round_trip.rs"),
        r#"use spx_pg_rust_calling_consumer::{diagnostics, Provider, TRUSTED_BINDING_BYTES, TRUSTED_DESCRIPTOR_BYTES};
#[test]
fn exact_malformed_trusted_bytes_reach_the_provider_after_the_mutation() {
    let before = diagnostics::live_allocations();
    let mut provider = Provider::open(TRUSTED_DESCRIPTOR_BYTES, TRUSTED_BINDING_BYTES)
        .expect("the mutated descriptor envelope must admit its exact trusted bytes");
    assert!(
        diagnostics::live_allocations() > before,
        "opening the weakened consumer must reach the provider allocation"
    );
    provider.close().expect("the reached provider must close cleanly");
    assert_eq!(diagnostics::live_allocations(), before);
}
"#,
    )
    .unwrap();
    let target = workspace.0.join("cargo-target");
    let mut cargo = Command::new(tool("CARGO", "cargo"));
    cargo
        .current_dir(&crate_root)
        .env("CARGO_TARGET_DIR", &target)
        .env("SPX_PG_PROVIDER_LIB_DIR", &lib_dir)
        .env("SPX_PG_PROVIDER_LIB_NAME", "spx_pg_reference_provider")
        .env_remove("RUSTC_WRAPPER")
        .args(["test", "--", "--test-threads=1"]);
    run_cargo(
        &mut cargo,
        &format!("[{label}] run Rust descriptor-envelope mutant"),
    );
}

#[test]
fn generated_native_consumers_reject_a_byte_identical_malformed_trusted_descriptor_before_open() {
    assert_c11_and_cxx17_consumers_reject("native", &malformed_descriptor(), &binding());
}

#[test]
fn generated_rust_consumer_rejects_a_byte_identical_malformed_trusted_descriptor_before_open() {
    assert_rust_consumer_rejects("rust", &malformed_descriptor(), &binding());
}

/// Issue #173: every case of the closed malformed-trusted manifest, through
/// really compiled and executed C11 and C++17 consumers.
///
/// Each case's bytes are simultaneously the consumer's embedded trusted
/// descriptor and the caller's submission, so
/// `spx_pg_ccc_verify_pairing`'s structured replay sees identical fields and
/// only `spx_pg_ccc_parse_descriptor_v1` can refuse. Deleting any single
/// branch of that function therefore turns exactly one case green-to-red rather than
/// being masked by the pairing check.
#[test]
fn malformed_trusted_corpus_is_refused_by_the_c11_and_cxx17_consumers() {
    let cases = malformed_trusted_descriptor_cases();
    assert_eq!(cases.len(), 6, "the manifest is closed");
    for (name, bytes, _, _) in cases {
        assert_c11_and_cxx17_consumers_reject(name, &bytes, &binding());
    }
}

/// The same closed manifest through the really built and executed generated
/// Rust consumer, so a divergence between the C11 and Rust transliterations
/// of the same frozen envelope rules fails here rather than silently
/// widening one language's admitted set.
#[test]
fn malformed_trusted_corpus_is_refused_by_the_rust_consumer() {
    let cases = malformed_trusted_descriptor_cases();
    assert_eq!(cases.len(), 6, "the manifest is closed");
    for (name, bytes, _, _) in cases {
        assert_rust_consumer_rejects(name, &bytes, &binding());
    }
}

/// Persistent executable mutation controls for the six #173 branches whose
/// hostile bytes are also the consumer's embedded trusted bytes.  Each
/// temporary source mutation makes exactly one case reach the provider;
/// without this check, merely listing/refusing the cases could leave a dead
/// branch or a masking validation layer undetected.
#[test]
fn each_requested_descriptor_envelope_mutation_is_detected_by_native_consumers() {
    let cases = malformed_trusted_descriptor_mutation_cases();
    assert_eq!(
        cases.len(),
        6,
        "the requested mutation-control set is closed"
    );
    for (name, bytes, _, _) in cases {
        assert_c11_mutation_is_detected(name, &bytes, &binding());
        assert_rust_mutation_is_detected(name, &bytes, &binding());
    }
}
