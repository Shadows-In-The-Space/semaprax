//! Runtime regression for #173: byte identity alone cannot authorize a
//! calling consumer.  The generated package deliberately embeds a truncated
//! descriptor and the caller submits those exact embedded bytes.  The native
//! provider would accept that byte-exact pair, so the generated consumer must
//! reject the descriptor envelope itself before it can allocate or call it.

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

#[test]
fn generated_native_consumers_reject_a_byte_identical_malformed_trusted_descriptor_before_open() {
    let bytes = malformed_descriptor();
    let binding = binding();
    let (input, output) = shapes();
    let workspace = Workspace::new("native");
    let provider = compile_provider(&workspace.0, &bytes, &binding);
    let clang = tool("CLANG", "clang");

    let c = generate_c_calling_consumer(&bytes, &binding, &input, &output)
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
        "build C11 malformed-descriptor driver",
    );
    run(
        Command::new(&c_binary).current_dir(&c_root),
        "run C11 malformed-descriptor driver",
    );

    let cxx = generate_cxx_calling_consumer(&bytes, &binding, &input, &output)
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
        "compile C11 consumer for C++17 driver",
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
        "build C++17 malformed-descriptor driver",
    );
    run(
        Command::new(&cxx_binary).current_dir(&cxx_root),
        "run C++17 malformed-descriptor driver",
    );
}

#[test]
fn generated_rust_consumer_rejects_a_byte_identical_malformed_trusted_descriptor_before_open() {
    let bytes = malformed_descriptor();
    let binding = binding();
    let (input, output) = shapes();
    let consumer = generate_rust_calling_consumer(&bytes, &binding, &input, &output)
        .expect("generation keeps its byte-oriented API for this regression");
    let workspace = Workspace::new("rust");
    let provider = compile_provider(&workspace.0, &bytes, &binding);
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
    run_cargo(&mut cargo, "run Rust malformed-descriptor driver");
}
