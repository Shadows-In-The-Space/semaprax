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

use super::c_calling_consumer::{fixture_binding, fixture_descriptor_bytes};

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
fn shape(count: usize) -> RecordShape {
    RecordShape::new(
        (0..count)
            .map(|index| OwnedByteField::new(format!("settlement.field{index}")))
            .collect(),
    )
}

#[test]
fn generated_c_and_cpp_match_fixture_bytes_and_execute_the_settlement_matrix() {
    let workspace = Workspace::new();
    let descriptor = fixture_descriptor_bytes();
    let binding = fixture_binding();
    for count in [1, 2, 3, 256] {
        let shape = shape(count);
        let generated = generate_cxx_calling_consumer(&descriptor, &binding, &shape, &shape).unwrap();
        write_files(&workspace.0.join(count.to_string()), generated.files());
    }
    // --generated compares every executed C/C++ asset byte-for-byte against
    // actual generator output before any compiler sees it. It fails on drift.
    run(Command::new(env::var_os("PYTHON").unwrap_or_else(|| "python3".into()))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("scripts/public_generic_consumer_settlement.py")
        .arg("--generated")
        .arg(&workspace.0)
        .arg("--output")
        .arg(workspace.0.join("evidence")));
}

#[test]
fn generated_rust_explicit_settlement_executes_against_the_physical_provider() {
    let workspace = Workspace::new();
    let descriptor = fixture_descriptor_bytes();
    let binding = fixture_binding();
    let shape = shape(2);
    let generated = generate_rust_calling_consumer(&descriptor, &binding, &shape, &shape).unwrap();
    write_files(&workspace.0, generated.files());
    let field = |index| {
        let identity = format!("settlement.field{index}");
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
        render_reference_provider(&descriptor, &binding),
        include_str!("consumer_settlement/rust_shim.c")
    );
    fs::write(workspace.0.join("provider.c"), source).unwrap();
    run(Command::new(env::var_os("CLANG").unwrap_or_else(|| "clang".into()))
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
        ]));
    run(Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()))
        .current_dir(&workspace.0)
        .args(["rcs", "libspx_pg_reference_provider.a", "provider.o"]));
    // The external generator has no dependencies and does not emit a lockfile.
    // Materialize that lock offline before enforcing --locked execution.
    run(Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .current_dir(&workspace.0)
        .args(["generate-lockfile", "--offline"]));
    run(Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
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
        ]));
}
