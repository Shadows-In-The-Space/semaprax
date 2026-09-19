//! Test fixtures shared across the four value-focused suites below. Each
//! submodule states, per test, what regression it exists to catch.

mod credential_refusal;
mod determinism;
mod hostile_input;
mod structural_validity;

use std::path::PathBuf;
use std::sync::Mutex;

use crate::OciPlan;

/// [`crate::validation::refuse_if_credential_environment_present`] reads the
/// real process environment, which is global process state shared by every
/// test thread in this binary. Any test that mutates a credential-shaped
/// variable, and any test that calls [`crate::build_and_publish`] (which
/// checks that same environment), must serialize against every other one:
/// otherwise a credential-mutating test can make an unrelated concurrent
/// test observe a spurious refusal, exactly as this suite discovered the
/// first time it ran multi-threaded.
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn fixture_wasm() -> Vec<u8> {
    // This crate never parses or validates Wasm structure -- it only
    // packages bytes handed to it -- so any deterministic byte string
    // stands in for a real compiler-produced module.
    b"\0asm\x01\0\0\0deterministic-fixture-module".to_vec()
}

pub(crate) fn fixture_plan() -> OciPlan {
    let wasm_bytes = fixture_wasm();
    let wasm_sha256 = crate::render::sha256_digest_fact(&wasm_bytes);
    OciPlan {
        project_name: "calculator".to_owned(),
        project_revision: format!("sha256:{}", "1".repeat(64)),
        workspace_revision: format!("sha256:{}", "2".repeat(64)),
        project_graph_digest: format!("sha256:{}", "3".repeat(64)),
        entry_module: "calculator.app".to_owned(),
        wasm_bytes,
        wasm_sha256,
    }
}

/// A fresh, not-yet-created directory path private to one test invocation.
/// The path itself is test scaffolding only: by design (see
/// `docs/OCI-DEPLOYABLE-ARTIFACT-V1.md`) no emitted byte ever encodes it, so
/// using a process/thread/time-derived nonce here does not compromise the
/// determinism the emitted *content* is tested for.
pub(crate) fn fresh_output_dir(label: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "semaprax-oci-package-test-{label}-{nonce}-{:?}",
        std::thread::current().id()
    ));
    path
}
