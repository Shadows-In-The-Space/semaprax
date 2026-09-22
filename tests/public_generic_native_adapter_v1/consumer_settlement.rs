//! #162 generated-consumer settlement. These Unix harnesses require their
//! toolchains and never count a missing compiler as a pass. Windows/MSVC
//! execution and Rust heap-allocation instrumentation are separate nonclaims.
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::public_generic_abi::native::template::render_reference_provider;
use semaprax::public_generic_consumer::cxx_calling::generate_cxx_calling_consumer;
use semaprax::public_generic_consumer::rust_calling::{
    generate_rust_calling_consumer, OwnedByteField, RecordShape,
};

use crate::public_generic_admitted_subject;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let root = env::temp_dir().join(format!(
            "spx-consumer-settlement-{}-{}",
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
fn run(command: &mut Command) {
    let output = command
        .output()
        .expect("selected settlement gate requires its toolchain");
    assert!(
        output.status.success(),
        "{command:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn write_files(root: &Path, files: &[(String, String)]) {
    for (name, contents) in files {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}
fn write_verified_subject(
    root: &Path,
    subject: &public_generic_admitted_subject::NativeAdmittedSubject,
) {
    fs::create_dir_all(root).unwrap();
    fs::write(
        root.join("verified-descriptor.bin"),
        subject.descriptor_bytes(),
    )
    .unwrap();
    fs::write(
        root.join("verified-binding.bin"),
        subject.binding().encode(),
    )
    .unwrap();
    fs::write(
        root.join("verified-identities.json"),
        serde_json::to_vec(subject.leaf_identities()).unwrap(),
    )
    .unwrap();
}
fn shape(leaf_identities: &[String]) -> RecordShape {
    RecordShape::new(
        leaf_identities
            .iter()
            .cloned()
            .map(OwnedByteField::new)
            .collect(),
    )
}

#[test]
fn generated_c_and_cpp_match_fixture_bytes_and_execute_the_settlement_matrix() {
    let workspace = Workspace::new();
    for count in [1, 2, 3, 256] {
        let subject = public_generic_admitted_subject::native_admitted_subject(count);
        let shape = shape(subject.leaf_identities());
        let generated = generate_cxx_calling_consumer(
            subject.descriptor_bytes(),
            subject.binding(),
            &shape,
            &shape,
        )
        .unwrap();
        let root = workspace.0.join(count.to_string());
        write_files(&root, generated.files());
        write_verified_subject(&root, &subject);
    }
    // --generated compares every executed C/C++ asset byte-for-byte against
    // actual generator output before any compiler sees it. It fails on drift.
    run(
        Command::new(env::var_os("PYTHON").unwrap_or_else(|| "python3".into()))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg("scripts/public_generic_consumer_settlement.py")
            .arg("--generated")
            .arg(&workspace.0)
            .arg("--output")
            .arg(workspace.0.join("evidence")),
    );
}

#[test]
fn generated_rust_explicit_settlement_executes_against_the_physical_provider() {
    let workspace = Workspace::new();
    let subject = public_generic_admitted_subject::native_admitted_subject(2);
    let shape = shape(subject.leaf_identities());
    let generated = generate_rust_calling_consumer(
        subject.descriptor_bytes(),
        subject.binding(),
        &shape,
        &shape,
    )
    .unwrap();
    write_files(&workspace.0, generated.files());
    let field = |index: usize| {
        let identity = &subject.leaf_identities()[index];
        let suffix: String = identity.bytes().map(|byte| format!("{byte:02x}")).collect();
        format!("field_{suffix}")
    };
    let driver = include_str!("consumer_settlement/rust_driver.rs.txt")
        .replace("@FIELD0@", &field(0))
        .replace("@FIELD1@", &field(1));
    fs::write(workspace.0.join("tests/settlement.rs"), driver).unwrap();
    let source = format!(
        "{}\n{}\n#define spx_pg_result_export_v1 rs_real_export\n#define spx_pg_provider_close_v1 rs_real_close\n{}\n{}",
        include_str!("allocations.c"),
        include_str!("settlement_corpus/observations.c"),
        render_reference_provider(subject.descriptor_bytes(), subject.binding()),
        include_str!("consumer_settlement/rust_shim.c")
    );
    fs::write(workspace.0.join("provider.c"), source).unwrap();
    run(
        Command::new(env::var_os("CLANG").unwrap_or_else(|| "clang".into()))
            .current_dir(&workspace.0)
            .args([
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-c",
                "provider.c",
                "-o",
                "provider.o",
            ]),
    );
    run(
        Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()))
            .current_dir(&workspace.0)
            .args(["rcs", "libspx_pg_reference_provider.a", "provider.o"]),
    );
    // The external generator has no dependencies and does not emit a lockfile.
    // Materialize that lock offline before enforcing --locked execution.
    run(
        Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(&workspace.0)
            .args(["generate-lockfile", "--offline"]),
    );
    run(
        Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(&workspace.0)
            .env("SPX_PG_PROVIDER_LIB_DIR", &workspace.0)
            .env("SPX_PG_PROVIDER_LIB_NAME", "spx_pg_reference_provider")
            .env("CARGO_TARGET_DIR", workspace.0.join("target"))
            .env_remove("RUSTC_WRAPPER")
            .args([
                "test",
                "--locked",
                "--offline",
                "--lib",
                "--test",
                "settlement",
                "--",
                "--test-threads=1",
            ]),
    );
}

#[test]
fn generated_callers_share_verified_descriptor_instance_and_cleanup_facts() {
    let first = public_generic_admitted_subject::native_admitted_subject(2);
    let again = public_generic_admitted_subject::native_admitted_subject(2);
    assert_eq!(first.descriptor_bytes(), again.descriptor_bytes());
    assert_eq!(first.descriptor_digest(), again.descriptor_digest());
    assert_eq!(
        first
            .binding()
            .carrier_binding()
            .descriptor_identity_digest(),
        first.descriptor_digest(),
        "the physical binding must name the independently verified descriptor identity"
    );
    assert_eq!(first.input_instance_term(), first.result_instance_term());
    assert!(
        first
            .input_instance_term()
            .contains("admitted.subject.envelope"),
        "the fixture must retain the generic envelope instance identity"
    );
    assert!(!first.cleanup_plan_digest().is_empty());
    assert_eq!(first.leaf_identities().len(), 2);
    assert_eq!(
        public_generic_admitted_subject::native_admitted_subject(3)
            .leaf_identities()
            .len(),
        3,
        "each generated caller shape comes from a matching admitted source subject"
    );
}
