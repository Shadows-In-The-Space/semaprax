//! Executes the admission matrix using the actual production C renderer.
//! The Python gate first requires exact source equality; it cannot substitute
//! a hand-assembled provider when the real renderer's output differs.
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::Ordering;

use semaprax::public_generic_abi::native::template::render_reference_provider;

use super::{native_binding, DESCRIPTOR_FIXTURE, NEXT};

struct Workspace(PathBuf);
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn actual_native_renderer_enforces_single_owner_and_reentrant_refusal() {
    let workspace = Workspace(std::env::temp_dir().join(format!(
        "spx-thread-admission-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    fs::create_dir(&workspace.0).unwrap();
    let provider = workspace.0.join("provider.c");
    fs::write(
        &provider,
        render_reference_provider(DESCRIPTOR_FIXTURE, &native_binding()),
    )
    .unwrap();
    let output = Command::new(std::env::var_os("PYTHON").unwrap_or_else(|| "python3".into()))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("scripts/public_generic_settlement_threads.py")
        .arg("--generated-provider")
        .arg(&provider)
        .output()
        .expect("selected admission gate requires Python and a pthread-capable C11 compiler");
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
