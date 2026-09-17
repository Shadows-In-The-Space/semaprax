//! #162: generate real TypeScript assets, compare all ten files with the
//! template fixture and run the same lifecycle/hostility gate. No missing
//! tool is counted as a pass. This remains the hand-assembled endpoint-only
//! Wasm fixture with host-owned bookkeeping, not compiler/provider proof.
#![cfg(unix)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::public_generic_consumer::rust_calling::{OwnedByteField, RecordShape};
use semaprax::public_generic_consumer::typescript_calling::generate_typescript_calling_consumer;

use super::reference_wasm_module;
use super::typescript_calling_consumer::{fixture_binding, fixture_descriptor_bytes};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let root = env::temp_dir().join(format!(
            "spx-ts-settlement-{}-{}",
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
        .expect("selected TypeScript settlement gate requires its toolchains");
    assert!(
        output.status.success(),
        "{command:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn python() -> Command {
    let mut command = Command::new(env::var_os("PYTHON").unwrap_or_else(|| "python3".into()));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("scripts/public_generic_typescript_settlement.py");
    command
}
fn write_files(root: &Path, files: &[(String, String)]) {
    for (name, contents) in files {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}

#[test]
fn actual_generated_typescript_matches_all_assets_and_executes_settlement() {
    let workspace = Workspace::new();
    let subjects = workspace.0.join("subjects");
    let generated = workspace.0.join("generated");
    run(python().arg("--write-subjects").arg("--output").arg(&subjects));
    let inventory: serde_json::Value =
        serde_json::from_slice(&fs::read(subjects.join("subjects.json")).unwrap()).unwrap();
    let rows = inventory.as_array().unwrap();
    assert_eq!(rows.len(), 16);
    let descriptor = fixture_descriptor_bytes();
    for row in rows {
        assert_eq!(row.as_object().unwrap().len(), 2);
        let label = row["label"].as_str().unwrap();
        assert!(label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        let count = usize::try_from(row["fields"].as_u64().unwrap()).unwrap();
        assert!([1, 2, 256].contains(&count));
        let module = fs::read(subjects.join(label).join("reference.wasm")).unwrap();
        if label.starts_with("fields-") {
            assert_eq!(module, reference_wasm_module::build_with_max_pages(257));
        } else if label == "grow-limit" {
            assert_eq!(module, reference_wasm_module::build_with_max_pages(1));
        }
        let shape = RecordShape::new(
            (0..count)
                .map(|index| OwnedByteField::new(format!("settlement.field{index}")))
                .collect(),
        );
        let consumer = generate_typescript_calling_consumer(
            &descriptor,
            &fixture_binding(&module),
            &shape,
            &shape,
        )
        .unwrap();
        // A distinct empty destination ensures missing generator output cannot
        // be silently supplied by the earlier template-assembly step.
        write_files(&generated.join(label), consumer.files());
        fs::write(generated.join(label).join("reference.wasm"), module).unwrap();
    }
    run(python()
        .arg("--generated")
        .arg(generated)
        .arg("--output")
        .arg(workspace.0.join("evidence")));
}

#[test]
fn legacy_wasm_fixture_is_unchanged_and_framing_capacity_is_explicit() {
    assert_eq!(
        reference_wasm_module::build(),
        reference_wasm_module::build_with_max_pages(256)
    );
    assert_ne!(
        reference_wasm_module::build(),
        reference_wasm_module::build_with_max_pages(257)
    );
    assert_ne!(
        reference_wasm_module::build(),
        reference_wasm_module::build_with_max_pages(1)
    );
}
