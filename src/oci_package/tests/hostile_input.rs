//! A dangerous identity shape must be refused with a stable error kind, not
//! sanitized and silently accepted. Every case here also asserts the output
//! directory was never created, proving the refusal happens before any
//! filesystem effect -- a weakened validator that let the bytes through
//! (perhaps escaping a separator instead of refusing it) would fail that
//! second assertion even if it happened not to crash.

use super::{fixture_plan, fresh_output_dir, TEST_LOCK};
use crate::oci_package::{build_and_publish, OciErrorKind};

fn assert_refused(mutate: impl FnOnce(&mut crate::oci_package::OciPlan), label: &str) {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut plan = fixture_plan();
    mutate(&mut plan);
    let out = fresh_output_dir(label);
    let error = build_and_publish(plan, &out).expect_err(label);
    assert_eq!(error.kind(), OciErrorKind::Identity, "{label}");
    assert!(!out.exists(), "{label}: refusal must precede any fs write");
}

#[test]
fn project_name_with_path_separator_is_refused() {
    assert_refused(
        |plan| plan.project_name = "a/b".to_owned(),
        "name-separator",
    );
    assert_refused(
        |plan| plan.project_name = "a\\b".to_owned(),
        "name-backslash",
    );
}

#[test]
fn project_name_with_traversal_sequence_is_refused() {
    assert_refused(
        |plan| plan.project_name = "../etc".to_owned(),
        "name-traversal",
    );
}

#[test]
fn project_name_with_nul_byte_is_refused() {
    assert_refused(|plan| plan.project_name = "a\0b".to_owned(), "name-nul");
}

#[test]
fn project_name_over_long_is_refused() {
    assert_refused(|plan| plan.project_name = "a".repeat(65), "name-overlong");
}

#[test]
fn entry_module_with_traversal_sequence_is_refused() {
    assert_refused(
        |plan| plan.entry_module = "..".to_owned(),
        "entry-traversal",
    );
    assert_refused(
        |plan| plan.entry_module = "a/../b".to_owned(),
        "entry-traversal-embedded",
    );
}

#[test]
fn entry_module_with_separator_is_refused() {
    assert_refused(
        |plan| plan.entry_module = "a/b".to_owned(),
        "entry-separator",
    );
}

#[test]
fn entry_module_with_nul_byte_is_refused() {
    assert_refused(|plan| plan.entry_module = "a\0b".to_owned(), "entry-nul");
}

#[test]
fn entry_module_over_long_is_refused() {
    assert_refused(|plan| plan.entry_module = "a".repeat(129), "entry-overlong");
}

#[test]
fn malformed_digest_facts_are_refused() {
    assert_refused(
        |plan| plan.project_revision = "not-a-digest".to_owned(),
        "digest-malformed",
    );
    assert_refused(
        |plan| plan.workspace_revision = "sha256:TOOSHORT".to_owned(),
        "digest-wrong-length",
    );
    assert_refused(
        |plan| plan.project_graph_digest = format!("sha256:{}", "F".repeat(64)),
        "digest-uppercase",
    );
}

/// The caller's claimed digest must match the bytes it actually hands over.
/// This is the one check that is not about shape at all: it catches a
/// caller (or an attacker sitting between two build stages) that swapped
/// the Wasm payload without updating its digest.
#[test]
fn wasm_bytes_digest_mismatch_is_refused() {
    assert_refused(
        |plan| plan.wasm_bytes = b"tampered".to_vec(),
        "wasm-digest-mismatch",
    );
}

#[test]
fn empty_wasm_module_is_refused() {
    assert_refused(
        |plan| {
            plan.wasm_bytes = Vec::new();
            plan.wasm_sha256 = crate::oci_package::render::sha256_digest_fact(&[]);
        },
        "wasm-empty",
    );
}

#[test]
fn oversized_wasm_module_is_refused() {
    assert_refused(
        |plan| {
            let bytes = vec![0u8; crate::oci_package::MAX_WASM_BYTES + 1];
            plan.wasm_sha256 = crate::oci_package::render::sha256_digest_fact(&bytes);
            plan.wasm_bytes = bytes;
        },
        "wasm-oversized",
    );
}

/// The output path itself is refused, not silently truncated at the NUL
/// byte, if it carries one.
#[test]
fn output_path_with_nul_byte_is_refused() {
    let _guard = TEST_LOCK.lock().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let out =
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/semaprax-oci\0hostile"));
        let error = build_and_publish(fixture_plan(), &out).expect_err("nul byte output path");
        assert_eq!(error.kind(), OciErrorKind::Identity);
    }
}
