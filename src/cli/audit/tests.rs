//! Tests for the `semaprax audit inspect|verify|diff` CLI front.
//!
//! Every fixture here is built through `audit_capsule::render_capsule`
//! rather than hand-written JSON, so a change to the front's own parsing or
//! path handling is what these tests exercise -- `audit_capsule` itself
//! already carries its own exhaustive hostile-input suite.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::audit_capsule::{render_capsule, sha256_digest, AssociationEdge, ObjectRef, Profile};

use super::*;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn scratch_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "semaprax-audit-cli-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).expect("scratch directory must be creatable");
    path
}

const OBJECT_A_BYTES: &[u8] = b"program-root bytes";
const OBJECT_B_BYTES: &[u8] = b"semantic-transaction bytes";
const OBJECT_C_BYTES: &[u8] = b"assurance-manifest bytes";
const OBJECT_D_BYTES: &[u8] = b"source-projection bytes";

fn change_subject(revision: &str) -> BTreeMap<String, String> {
    let mut subject = BTreeMap::new();
    subject.insert(
        "source_digest".to_owned(),
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    );
    subject.insert(
        "root_digest".to_owned(),
        "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
    );
    subject.insert("revision".to_owned(), revision.to_owned());
    subject.insert(
        "compiler_version".to_owned(),
        env!("CARGO_PKG_VERSION").to_owned(),
    );
    subject
}

fn base_nonclaims() -> Vec<String> {
    audit_capsule::nonclaims::ALWAYS_REQUIRED_NONCLAIMS
        .iter()
        .map(|entry| (*entry).to_owned())
        .collect()
}

/// A minimal, valid `change`-profile capsule (all four required object
/// types, no associations, no signatures, no transparency) plus the
/// retained bytes each of its objects declares, keyed by object id.
fn valid_change_capsule(revision: &str) -> (Vec<u8>, BTreeMap<String, Vec<u8>>) {
    let objects = vec![
        ObjectRef {
            id: "obj-a-program-root".to_owned(),
            object_type: "program-root".to_owned(),
            schema: "semaprax.program-root.v3".to_owned(),
            digest: sha256_digest(OBJECT_A_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
        ObjectRef {
            id: "obj-b-semantic-transaction".to_owned(),
            object_type: "semantic-transaction".to_owned(),
            schema: "semaprax.project-candidate-semantic-delta.v1".to_owned(),
            digest: sha256_digest(OBJECT_B_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
        ObjectRef {
            id: "obj-c-assurance-manifest".to_owned(),
            object_type: "assurance-manifest".to_owned(),
            schema: "semaprax.assurance-manifest.v1".to_owned(),
            digest: sha256_digest(OBJECT_C_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
        ObjectRef {
            id: "obj-d-source-projection".to_owned(),
            object_type: "source-projection".to_owned(),
            schema: "semaprax.program-root.v3".to_owned(),
            digest: sha256_digest(OBJECT_D_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
    ];
    let associations = vec![AssociationEdge {
        from_id: "obj-b-semantic-transaction".to_owned(),
        relation: "derived_from".to_owned(),
        to_id: "obj-a-program-root".to_owned(),
    }];
    let manifest_bytes = render_capsule(
        Profile::Change,
        &change_subject(revision),
        &objects,
        &associations,
        &[],
        None,
        &base_nonclaims(),
    )
    .expect("a minimal well-formed change capsule must render");

    let mut object_bytes = BTreeMap::new();
    object_bytes.insert("obj-a-program-root".to_owned(), OBJECT_A_BYTES.to_vec());
    object_bytes.insert(
        "obj-b-semantic-transaction".to_owned(),
        OBJECT_B_BYTES.to_vec(),
    );
    object_bytes.insert(
        "obj-c-assurance-manifest".to_owned(),
        OBJECT_C_BYTES.to_vec(),
    );
    object_bytes.insert(
        "obj-d-source-projection".to_owned(),
        OBJECT_D_BYTES.to_vec(),
    );
    (manifest_bytes, object_bytes)
}

/// Writes a capsule manifest plus an objects directory to a fresh scratch
/// directory and returns (manifest_path, objects_dir).
fn write_fixture(label: &str, revision: &str) -> (PathBuf, PathBuf) {
    let (manifest_bytes, object_bytes) = valid_change_capsule(revision);
    let root = scratch_dir(label);
    let manifest_path = root.join("capsule.json");
    fs::write(&manifest_path, &manifest_bytes).expect("manifest must be writable");
    let objects_dir = root.join("objects");
    fs::create_dir_all(&objects_dir).expect("objects dir must be creatable");
    for (id, bytes) in &object_bytes {
        fs::write(objects_dir.join(id), bytes).expect("object file must be writable");
    }
    (manifest_path, objects_dir)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

// ---------------------------------------------------------------------
// `parse`: negative controls for the argument grammar. Each malformed
// input here must be rejected with exit code 2 before any path is opened;
// removing a guard would let a malformed invocation reach `std::fs::read`.
// ---------------------------------------------------------------------

#[test]
fn parse_admits_inspect_with_exactly_one_capsule_path() {
    match parse(&strings(&["inspect", "capsule.json"])) {
        Ok(AuditCommand::Inspect(path)) => assert_eq!(path, PathBuf::from("capsule.json")),
        _ => panic!("expected Inspect"),
    }
    for malformed in [
        &[][..],
        &["inspect"][..],
        &["inspect", "capsule.json", "extra"][..],
        &["inspect", ""][..],
        &["inspect", "--json"][..],
        &["bogus", "capsule.json"][..],
    ] {
        assert!(parse(&strings(malformed)).is_err(), "{malformed:?}");
    }
}

#[test]
fn parse_admits_verify_with_capsule_and_objects_dir_and_known_flags_only() {
    match parse(&strings(&["verify", "capsule.json", "objects"])) {
        Ok(AuditCommand::Verify(options)) => {
            assert_eq!(options.capsule, PathBuf::from("capsule.json"));
            assert_eq!(options.objects_dir, PathBuf::from("objects"));
            assert!(options.required_roles.is_empty());
        }
        _ => panic!("expected Verify"),
    }
    match parse(&strings(&[
        "verify",
        "capsule.json",
        "objects",
        "--require-role",
        "approver",
        "--now",
        "1000",
    ])) {
        Ok(AuditCommand::Verify(options)) => {
            assert_eq!(options.required_roles, vec!["approver".to_owned()]);
            assert_eq!(options.verification_time_unix_seconds, Some(1000));
        }
        _ => panic!("expected Verify with flags"),
    }
    for malformed in [
        &["verify"][..],
        &["verify", "capsule.json"][..],
        &["verify", "capsule.json", "objects", "--unknown-flag", "x"][..],
        &["verify", "capsule.json", "objects", "--require-role"][..],
        &["verify", "capsule.json", "objects", "stray-positional"][..],
        &["verify", "--flag-shaped", "objects"][..],
    ] {
        assert!(
            parse(&strings(malformed)).is_err(),
            "expected rejection for {malformed:?}"
        );
    }
}

#[test]
fn parse_admits_diff_with_exactly_two_capsule_paths() {
    match parse(&strings(&["diff", "a.json", "b.json"])) {
        Ok(AuditCommand::Diff(before, after)) => {
            assert_eq!(before, PathBuf::from("a.json"));
            assert_eq!(after, PathBuf::from("b.json"));
        }
        _ => panic!("expected Diff"),
    }
    for malformed in [
        &["diff"][..],
        &["diff", "a.json"][..],
        &["diff", "a.json", "b.json", "c.json"][..],
    ] {
        assert!(parse(&strings(malformed)).is_err(), "{malformed:?}");
    }
}

// ---------------------------------------------------------------------
// Path-traversal guard: the negative control for `is_safe_object_id` /
// `object_bytes_from_directory`. Deleting the guard would let a capsule
// whose object id is shaped like a traversal path make this front read a
// file outside the objects directory the caller named.
// ---------------------------------------------------------------------

#[test]
fn a_traversal_shaped_object_id_is_rejected_before_any_file_is_read() {
    assert!(is_safe_object_id("plain-id"));
    assert!(is_safe_object_id("obj-a-program-root"));
    for hostile in ["../secret", "../../etc/passwd", "/etc/passwd", "..", "."] {
        assert!(!is_safe_object_id(hostile), "{hostile:?} must be rejected");
    }

    // End to end: a capsule object whose id is traversal-shaped must fail
    // closed with this front's own document error, never attempt to read
    // outside `objects_dir`, and never reach `audit_capsule::verify_capsule`
    // at all. Built through typed `ObjectRef`s (not string surgery on
    // rendered JSON) so this does not depend on the manifest's on-the-wire
    // key order: only the fourth object's id is hostile, and the
    // association graph never references it, so this is a clean, minimal
    // reproduction of exactly the traversal case.
    let objects = vec![
        ObjectRef {
            id: "obj-a-program-root".to_owned(),
            object_type: "program-root".to_owned(),
            schema: "semaprax.program-root.v3".to_owned(),
            digest: sha256_digest(OBJECT_A_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
        ObjectRef {
            id: "obj-b-semantic-transaction".to_owned(),
            object_type: "semantic-transaction".to_owned(),
            schema: "semaprax.project-candidate-semantic-delta.v1".to_owned(),
            digest: sha256_digest(OBJECT_B_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
        ObjectRef {
            id: "obj-c-assurance-manifest".to_owned(),
            object_type: "assurance-manifest".to_owned(),
            schema: "semaprax.assurance-manifest.v1".to_owned(),
            digest: sha256_digest(OBJECT_C_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
        ObjectRef {
            // A source-projection object whose id is shaped like a
            // traversal path, not a benign id -- `render_capsule` places
            // no character restriction on ids, so this is admitted as a
            // structurally well-formed capsule.
            id: "../../outside-objects-dir".to_owned(),
            object_type: "source-projection".to_owned(),
            schema: "semaprax.program-root.v3".to_owned(),
            digest: sha256_digest(OBJECT_D_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
    ];
    let manifest_bytes = render_capsule(
        Profile::Change,
        &change_subject("r-traversal"),
        &objects,
        &[],
        &[],
        None,
        &base_nonclaims(),
    )
    .expect("a capsule with an unusually-shaped but valid object id must still render");

    let root = scratch_dir("traversal");
    let manifest_path = root.join("capsule.json");
    fs::write(&manifest_path, &manifest_bytes).unwrap();
    let objects_dir = root.join("objects");
    fs::create_dir_all(&objects_dir).unwrap();
    fs::write(objects_dir.join("obj-a-program-root"), OBJECT_A_BYTES).unwrap();
    fs::write(
        objects_dir.join("obj-b-semantic-transaction"),
        OBJECT_B_BYTES,
    )
    .unwrap();
    fs::write(objects_dir.join("obj-c-assurance-manifest"), OBJECT_C_BYTES).unwrap();
    // A real file exists exactly where the traversal would land if the
    // guard were removed, so a regression here would actually succeed
    // rather than merely misbehave silently.
    fs::write(root.join("outside-objects-dir"), OBJECT_D_BYTES).unwrap();

    let options = VerifyOptions {
        capsule: manifest_path,
        objects_dir,
        required_roles: Vec::new(),
        revoked_identities: Vec::new(),
        trusted_logs: Vec::new(),
        minimum_accepted_checkpoint_size: 0,
        verification_time_unix_seconds: Some(0),
    };
    let error = run_verify(&options).expect_err("a traversal-shaped id must be rejected");
    assert_eq!(error.code, "SPX-Z920");
    assert!(
        error.message.contains("plain path segment"),
        "{}",
        error.message
    );
}

// ---------------------------------------------------------------------
// End-to-end wiring: proves `inspect`, `verify`, and `diff` actually call
// through to `audit_capsule` and produce a report, not merely that the
// argument grammar parses.
// ---------------------------------------------------------------------

#[test]
fn inspect_reports_the_capsules_own_structure() {
    let (manifest_path, _objects_dir) = write_fixture("inspect", "r1");
    let report = run_inspect(&manifest_path).expect("a well-formed capsule must inspect");
    assert!(report.contains("profile: change"));
    assert!(report.contains("objects: 4"));
    assert!(report.contains("obj-a-program-root"));
    assert!(report.contains("status: INSPECTED"));
    // Never claims verification happened.
    assert!(!report.contains("VERIFIED"));
}

#[test]
fn verify_succeeds_against_the_matching_objects_directory_and_never_claims_signing() {
    let (manifest_path, objects_dir) = write_fixture("verify-ok", "r2");
    let options = VerifyOptions {
        capsule: manifest_path,
        objects_dir,
        required_roles: Vec::new(),
        revoked_identities: Vec::new(),
        trusted_logs: Vec::new(),
        minimum_accepted_checkpoint_size: 0,
        verification_time_unix_seconds: Some(0),
    };
    let report = run_verify(&options).expect("a matching objects directory must verify");
    assert!(report.contains("status: VERIFIED (structural integrity only)"));
    assert!(report.contains("verified objects: 4"));
    // Every capsule's own required nonclaims must be printed, not summarized
    // away -- this is the property that stops a downstream reader from
    // mistaking a green report for a cryptographic signature check.
    for nonclaim in audit_capsule::nonclaims::ALWAYS_REQUIRED_NONCLAIMS {
        assert!(report.contains(nonclaim), "missing nonclaim {nonclaim}");
    }
    assert!(report.contains("no cryptographic signature verification"));
    assert!(!report.to_lowercase().contains("signed capsule"));
}

/// Negative control: this is the exact test that proves `verify` performs
/// real byte-level integrity checking rather than trusting the manifest --
/// removing `object_bytes_from_directory`'s digest recomputation (delegated
/// to `check_object_bytes`) would let a substituted object pass silently.
#[test]
fn verify_fails_closed_when_an_object_file_does_not_match_its_declared_digest() {
    let (manifest_path, objects_dir) = write_fixture("verify-substituted", "r3");
    fs::write(objects_dir.join("obj-a-program-root"), b"substituted bytes").unwrap();
    let options = VerifyOptions {
        capsule: manifest_path,
        objects_dir,
        required_roles: Vec::new(),
        revoked_identities: Vec::new(),
        trusted_logs: Vec::new(),
        minimum_accepted_checkpoint_size: 0,
        verification_time_unix_seconds: Some(0),
    };
    let error = run_verify(&options).expect_err("a substituted object must fail closed");
    assert_eq!(error.code, "SPX-Z904");
    assert!(error.message.contains("substituted"), "{}", error.message);
}

#[test]
fn verify_fails_closed_when_an_object_file_is_missing() {
    let (manifest_path, objects_dir) = write_fixture("verify-missing", "r4");
    fs::remove_file(objects_dir.join("obj-a-program-root")).unwrap();
    let options = VerifyOptions {
        capsule: manifest_path,
        objects_dir,
        required_roles: Vec::new(),
        revoked_identities: Vec::new(),
        trusted_logs: Vec::new(),
        minimum_accepted_checkpoint_size: 0,
        verification_time_unix_seconds: Some(0),
    };
    let error = run_verify(&options).expect_err("a missing object file must fail closed");
    assert_eq!(error.code, "SPX-Z920");
}

#[test]
fn diff_reports_no_difference_for_identical_capsules() {
    let (manifest_path, _objects_dir) = write_fixture("diff-same", "r5");
    let report =
        run_diff(&manifest_path, &manifest_path).expect("a capsule must diff against itself");
    assert!(report.contains("no structural difference"));
}

#[test]
fn diff_reports_a_changed_object_digest_between_two_revisions() {
    let (before_path, _) = write_fixture("diff-before", "r6");
    let (after_manifest, after_objects) = valid_change_capsule("r7");
    let after_root = scratch_dir("diff-after");
    let after_path = after_root.join("capsule.json");
    fs::write(&after_path, &after_manifest).unwrap();
    let _ = after_objects; // objects aren't needed for a manifest-only diff

    let report = run_diff(&before_path, &after_path).expect("two change capsules must diff");
    assert!(report.contains("subject.revision: r6 -> r7"));
}

// ---------------------------------------------------------------------
// Determinism: the same inputs must produce byte-identical CLI output.
// This is the load-bearing property AGENTS.md requires of every
// contracted generated artifact; a nondeterministic report (e.g. from
// unordered iteration) would fail this test but pass every other one here.
// ---------------------------------------------------------------------

#[test]
fn inspect_and_verify_reports_are_byte_identical_across_repeated_runs() {
    let (manifest_path, objects_dir) = write_fixture("determinism", "r8");
    let first_inspect = run_inspect(&manifest_path).unwrap();
    let second_inspect = run_inspect(&manifest_path).unwrap();
    assert_eq!(first_inspect, second_inspect);

    let options = VerifyOptions {
        capsule: manifest_path,
        objects_dir,
        required_roles: Vec::new(),
        revoked_identities: Vec::new(),
        trusted_logs: Vec::new(),
        minimum_accepted_checkpoint_size: 0,
        verification_time_unix_seconds: Some(42),
    };
    let first_verify = run_verify(&options).unwrap();
    let second_verify = run_verify(&options).unwrap();
    assert_eq!(first_verify, second_verify);
}

// ---------------------------------------------------------------------
// Portability / authority: structural asserts on this front's own source
// text, mirroring `audit_capsule`'s own such tests.
// ---------------------------------------------------------------------

#[test]
fn this_front_spawns_no_process_and_reaches_no_network() {
    let source = include_str!("../audit.rs");
    assert!(!source.contains("std::process::Command"));
    assert!(!source.contains("TcpStream"));
    assert!(!source.contains("std::net::"));
}
