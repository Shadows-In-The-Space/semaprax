//! `semaprax release verify <release-dir>` (#168): the one documented command
//! a downloader runs over an unpacked release directory.
//!
//! The route is a thin front over `semaprax::release_provenance`, so these
//! cases assert the *command's* contract: it re-derives every digest from
//! held, no-follow bytes, fails closed with the owning module's exact stable
//! diagnostic code on each disagreement, changes nothing in the directory it
//! reads, and -- because no SEMAPRAX release is signed and no signing key or
//! keyless identity exists -- reports a successful run as a verification of an
//! *unsigned* release, both with and without a signature claim present.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

use semaprax::release_provenance::{
    ARCHIVE_PLATFORMS, TRUSTED_ISSUER, TRUSTED_REPOSITORY, TRUSTED_WORKFLOW_PATH,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

const TAG: &str = "v9.9.9";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_COMMIT: &str = "89abcdef0123456789abcdef0123456789abcdef";
const FAKE_DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn sha256(bytes: &[u8]) -> String {
    format!(
        "sha256:{:x}",
        semaprax::digest_hex::LowerHex(Sha256::digest(bytes))
    )
}

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "semaprax-release-verify-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).expect("scratch directory must be creatable");
    path
}

fn archive_name(platform: &str) -> String {
    let extension = if platform.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("semaprax-{TAG}-{platform}.{extension}")
}

/// Write three archives with real, distinct bytes and return the manifest
/// `artifacts` array computed from them -- real sizes, real digests.
fn write_archives(directory: &Path) -> String {
    let mut entries = Vec::new();
    for (index, platform) in ARCHIVE_PLATFORMS.iter().enumerate() {
        let name = archive_name(platform);
        // Not a real archive: nothing here unpacks or executes an artifact,
        // and the verifier only ever re-hashes the bytes it is pointed at.
        let bytes = format!("synthetic release archive {index} for {platform}\n").into_bytes();
        fs::write(directory.join(&name), &bytes).expect("archive must be writable");
        entries.push(format!(
            "    {{\"name\": \"{name}\", \"platform\": \"{platform}\", \"size\": {}, \"digest\": \"{}\"}}",
            bytes.len(),
            sha256(&bytes)
        ));
    }
    entries.join(",\n")
}

fn manifest_json(artifacts: &str, commit: &str) -> String {
    let version = TAG.strip_prefix('v').unwrap();
    format!(
        r#"{{
  "schema": "semaprax.release-manifest.v1",
  "version": "{version}",
  "tag": "{TAG}",
  "commit": "{commit}",
  "prerelease": true,
  "required_checks": ["alpha", "beta"],
  "changelog_section_digest": "{FAKE_DIGEST}",
  "artifacts": [
{artifacts}
  ]
}}"#
    )
}

fn provenance_json(artifacts: &str, commit: &str, manifest_bytes: &[u8]) -> String {
    let version = TAG.strip_prefix('v').unwrap();
    let manifest_digest = sha256(manifest_bytes);
    let workflow_identity = format!("{TRUSTED_REPOSITORY}/{TRUSTED_WORKFLOW_PATH}@refs/tags/{TAG}");
    format!(
        r#"{{
  "schema": "semaprax.release-provenance.v1",
  "version": "{version}",
  "tag": "{TAG}",
  "commit": "{commit}",
  "prerelease": true,
  "required_checks": ["alpha", "beta"],
  "artifacts": [
{artifacts}
  ],
  "manifest_digest": "{manifest_digest}",
  "source": {{"repository": "{TRUSTED_REPOSITORY}", "commit": "{commit}", "tag": "{TAG}"}},
  "builder": {{"workflow_identity": "{workflow_identity}", "run_id": "1", "run_attempt": "1"}},
  "toolchain": {{"rustc_version": "1.88.0", "cargo_locked": true}},
  "build_host_class": "github-hosted-ubuntu-24.04",
  "nonclaims": ["unsigned_without_a_paired_signature_claim", "not_a_reproducible_build_claim"]
}}"#
    )
}

fn claim_json(subject_digest: &str, issuer: &str) -> String {
    let workflow_ref = format!("{TRUSTED_REPOSITORY}/{TRUSTED_WORKFLOW_PATH}@refs/tags/{TAG}");
    let subject = format!("repo:{TRUSTED_REPOSITORY}:ref:refs/tags/{TAG}");
    format!(
        r#"{{
  "schema": "semaprax.release-signature-claim.v1",
  "subject_digest": "{subject_digest}",
  "subject_name": "release-provenance.json",
  "identity": {{"issuer": "{issuer}", "subject": "{subject}", "workflow_ref": "{workflow_ref}"}},
  "algorithm": "sigstore-cosign-bundle-v0.3",
  "signature": "FIXTURE-NOT-A-REAL-SIGNATURE",
  "certificate": "FIXTURE-NOT-A-REAL-CERTIFICATE"
}}"#
    )
}

/// A complete, self-consistent, unsigned release directory.
fn release_directory(label: &str) -> PathBuf {
    let directory = scratch(label);
    let artifacts = write_archives(&directory);
    let manifest = manifest_json(&artifacts, COMMIT);
    fs::write(directory.join("release-manifest.json"), &manifest).expect("manifest must write");
    let provenance = provenance_json(&artifacts, COMMIT, manifest.as_bytes());
    fs::write(directory.join("release-provenance.json"), &provenance)
        .expect("provenance must write");
    directory
}

fn verify(directory: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_semaprax"))
        .args(["release", "verify"])
        .arg(directory)
        .output()
        .expect("the release verify route must run")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Assert the command failed closed with exactly this stable code, printed
/// nothing on stdout, and left an exit status of 1.
fn assert_rejected(output: &Output, code: &str) {
    let message = stderr(output);
    assert_eq!(output.status.code(), Some(1), "{message}");
    assert!(output.stdout.is_empty(), "{message}");
    assert!(
        message.starts_with(&format!("error[{code}]: ")),
        "expected {code}, got: {message}"
    );
}

fn listing(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("release directory must be readable")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The documented success path. A complete unsigned release verifies, and the
/// report says in those words that it is unsigned: a successful verification
/// of an unsigned release is never evidence that a release was signed.
#[test]
fn release_verify_reports_a_verified_unsigned_release() {
    let directory = release_directory("ok");
    let before = listing(&directory);

    let output = verify(&directory);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
    let report = String::from_utf8(output.stdout.clone()).unwrap();

    assert!(
        report.contains("status: VERIFIED UNSIGNED RELEASE\n"),
        "{report}"
    );
    assert!(
        report.contains(
            "signature: absent; this directory carries no release-signature-claim.json\n"
        ),
        "{report}"
    );
    assert!(
        report.contains("no SEMAPRAX release is signed today"),
        "{report}"
    );
    assert!(
        report.contains("Not verified and not claimed: authenticity."),
        "{report}"
    );
    assert!(
        report.contains("Nothing was published, signed, executed, or installed.\n"),
        "{report}"
    );
    assert!(report.contains(&format!("tag {TAG}")), "{report}");
    assert!(report.contains(&format!("commit {COMMIT}")), "{report}");
    assert!(
        report.contains(&format!(
            "artifacts: {count} of {count} re-hashed from held reads",
            count = ARCHIVE_PLATFORMS.len()
        )),
        "{report}"
    );

    // Verification is read-only: nothing published, extracted, or executed.
    assert_eq!(listing(&directory), before);

    // Deterministic: the same directory renders byte-identical twice.
    let again = verify(&directory);
    assert_eq!(again.stdout, output.stdout);

    fs::remove_dir_all(&directory).ok();
}

/// A single substituted byte inside one archive is rejected, because the
/// command re-hashes every artifact from disk instead of trusting the size
/// and digest the manifest reports for it.
#[test]
fn release_verify_rejects_a_substituted_artifact() {
    let directory = release_directory("substituted");
    let target = directory.join(archive_name(ARCHIVE_PLATFORMS[0]));
    let mut bytes = fs::read(&target).unwrap();
    let last = bytes.len() - 1;
    bytes[last] = b'X';
    fs::write(&target, &bytes).unwrap();

    assert_rejected(&verify(&directory), "SPX-Z704");
    fs::remove_dir_all(&directory).ok();
}

/// The actual standalone route opens manifest archives with no-follow held
/// handles. A final-component symlink cannot redirect its digest check to an
/// unrelated file outside the manifest inventory.
#[cfg(unix)]
#[test]
fn release_verify_rejects_a_symlinked_manifest_artifact() {
    let directory = release_directory("symlink-artifact");
    let archive = directory.join(archive_name(ARCHIVE_PLATFORMS[0]));
    let target = directory.join("unrelated-target");
    fs::write(&target, b"unrelated target bytes").unwrap();
    fs::remove_file(&archive).unwrap();
    std::os::unix::fs::symlink(&target, &archive).unwrap();

    assert_rejected(&verify(&directory), "SPX-Z704");
    fs::remove_dir_all(&directory).ok();
}

/// A different regular file moved into a manifest name is still re-hashed
/// from the held bytes and rejected; replacing a symlink with a plain file
/// cannot evade the digest check.
#[test]
fn release_verify_rejects_a_replaced_manifest_artifact() {
    let directory = release_directory("replaced-artifact");
    let archive = directory.join(archive_name(ARCHIVE_PLATFORMS[0]));
    let replacement = directory.join("replacement");
    fs::write(&replacement, b"replacement archive bytes").unwrap();
    fs::remove_file(&archive).unwrap();
    fs::rename(&replacement, &archive).unwrap();

    assert_rejected(&verify(&directory), "SPX-Z704");
    fs::remove_dir_all(&directory).ok();
}

/// The unsigned CLI uses the same explicit aggregate cap as the offline
/// capability route, before reserving or reading a manifest-sized archive.
#[test]
fn release_verify_rejects_an_oversized_manifest_archive_before_reading_it() {
    let directory = release_directory("oversized-artifact");
    let manifest_path = directory.join("release-manifest.json");
    let mut manifest = fs::read_to_string(&manifest_path).unwrap();
    let marker = "\"size\": ";
    let size_start = manifest.find(marker).unwrap() + marker.len();
    let size_end = manifest[size_start..]
        .find(|character: char| !character.is_ascii_digit())
        .map(|offset| size_start + offset)
        .unwrap();
    manifest.replace_range(size_start..size_end, "134217729");
    let artifacts_start =
        manifest.find("  \"artifacts\": [\n").unwrap() + "  \"artifacts\": [\n".len();
    let artifacts_end = artifacts_start + manifest[artifacts_start..].find("\n  ]").unwrap();
    let provenance = provenance_json(
        &manifest[artifacts_start..artifacts_end],
        COMMIT,
        manifest.as_bytes(),
    );
    fs::write(&manifest_path, &manifest).unwrap();
    fs::write(directory.join("release-provenance.json"), provenance).unwrap();

    assert_rejected(&verify(&directory), "SPX-Z704");
    fs::remove_dir_all(&directory).ok();
}

/// A named artifact that is not in the directory at all is rejected; the
/// manifest's inventory is closed, so a missing file is a failure and not a
/// silently skipped entry.
#[test]
fn release_verify_rejects_a_missing_artifact() {
    let directory = release_directory("missing-artifact");
    fs::remove_file(directory.join(archive_name(ARCHIVE_PLATFORMS[1]))).unwrap();

    assert_rejected(&verify(&directory), "SPX-Z704");
    fs::remove_dir_all(&directory).ok();
}

/// A provenance statement describing a different commit no longer binds the
/// manifest bytes beside it.
#[test]
fn release_verify_rejects_a_provenance_statement_for_another_commit() {
    let directory = scratch("other-commit");
    let artifacts = write_archives(&directory);
    let manifest = manifest_json(&artifacts, COMMIT);
    fs::write(directory.join("release-manifest.json"), &manifest).unwrap();
    // Built over the same manifest bytes (so `manifest_digest` still matches)
    // but declaring a different commit: only the field-by-field binding check
    // catches this one.
    let provenance = provenance_json(&artifacts, OTHER_COMMIT, manifest.as_bytes());
    fs::write(directory.join("release-provenance.json"), &provenance).unwrap();

    assert_rejected(&verify(&directory), "SPX-Z702");
    fs::remove_dir_all(&directory).ok();
}

/// One edited byte in the manifest changes its digest, so the provenance
/// statement's recorded `manifest_digest` no longer describes it.
#[test]
fn release_verify_rejects_a_tampered_manifest() {
    let directory = release_directory("tampered-manifest");
    let path = directory.join("release-manifest.json");
    let manifest = fs::read_to_string(&path).unwrap();
    // Whitespace only: the JSON value is unchanged, the bytes are not.
    fs::write(
        &path,
        manifest.replace("\"prerelease\": true", "\"prerelease\":  true"),
    )
    .unwrap();

    assert_rejected(&verify(&directory), "SPX-Z702");
    fs::remove_dir_all(&directory).ok();
}

/// A release directory that does not present a document at all fails with
/// this front's own code, before any verification runs.
#[test]
fn release_verify_rejects_a_directory_without_a_provenance_document() {
    let directory = release_directory("no-provenance");
    fs::remove_file(directory.join("release-provenance.json")).unwrap();

    let output = verify(&directory);
    assert_rejected(&output, "SPX-Z705");
    assert!(
        stderr(&output).contains("release-provenance.json"),
        "{}",
        stderr(&output)
    );
    fs::remove_dir_all(&directory).ok();
}

/// An entry at the fixed claim name is not absence. In particular, a dangling
/// link must flow into the CLI's no-follow document reader and fail closed.
#[cfg(unix)]
#[test]
fn release_verify_rejects_a_dangling_signature_claim_link() {
    let directory = release_directory("dangling-claim-link");
    let claim = directory.join("release-signature-claim.json");
    std::os::unix::fs::symlink(directory.join("missing-claim-target"), &claim).unwrap();

    let output = verify(&directory);
    assert_rejected(&output, "SPX-Z705");
    assert!(
        stderr(&output).contains("release-signature-claim.json"),
        "{}",
        stderr(&output)
    );
    fs::remove_dir_all(&directory).ok();
}

/// A claim lifted from a different release is rejected: its `subject_digest`
/// was computed over other provenance bytes.
#[test]
fn release_verify_rejects_a_replayed_signature_claim() {
    let directory = release_directory("replayed-claim");
    fs::write(
        directory.join("release-signature-claim.json"),
        claim_json(FAKE_DIGEST, TRUSTED_ISSUER),
    )
    .unwrap();

    assert_rejected(&verify(&directory), "SPX-Z702");
    fs::remove_dir_all(&directory).ok();
}

/// A correctly bound claim naming an unapproved issuer is rejected by the
/// pinned identity policy.
#[test]
fn release_verify_rejects_a_claim_from_an_unapproved_issuer() {
    let directory = release_directory("wrong-issuer");
    let provenance = fs::read(directory.join("release-provenance.json")).unwrap();
    fs::write(
        directory.join("release-signature-claim.json"),
        claim_json(&sha256(&provenance), "https://issuer.example.invalid"),
    )
    .unwrap();

    assert_rejected(&verify(&directory), "SPX-Z703");
    fs::remove_dir_all(&directory).ok();
}

/// A structurally valid, correctly bound claim still does not make a release
/// signed: this repository verifies no cryptographic signature, so the status
/// stays `VERIFIED UNSIGNED RELEASE` and the report says why in those terms.
#[test]
fn a_bound_signature_claim_is_still_reported_as_an_unsigned_release() {
    let directory = release_directory("bound-claim");
    let provenance = fs::read(directory.join("release-provenance.json")).unwrap();
    fs::write(
        directory.join("release-signature-claim.json"),
        claim_json(&sha256(&provenance), TRUSTED_ISSUER),
    )
    .unwrap();

    let output = verify(&directory);
    assert!(output.status.success(), "{}", stderr(&output));
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(
        report.contains("status: VERIFIED UNSIGNED RELEASE\n"),
        "{report}"
    );
    assert!(
        report.contains(
            "signature: binding only; its signature and certificate bytes were NOT decoded or \
             cryptographically verified\n"
        ),
        "{report}"
    );
    assert!(
        report.contains("no SEMAPRAX release is signed today"),
        "{report}"
    );
    fs::remove_dir_all(&directory).ok();
}

/// The standalone executable has no Sigstore/cosign authority. Once a
/// directory presents signed offline material it must refuse rather than
/// continuing down the unsigned, binding-only report path; an embedding host
/// must supply the explicit offline verification capability instead.
#[test]
fn release_verify_refuses_offline_bundle_material_without_a_capability() {
    let directory = release_directory("offline-material-without-capability");
    fs::write(
        directory.join("release-provenance.bundle"),
        b"untrusted fixture bundle",
    )
    .unwrap();

    let output = verify(&directory);
    assert_rejected(&output, "SPX-Z706");
    assert!(
        stderr(&output).contains("no caller-supplied offline verification capability"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("VERIFIED UNSIGNED RELEASE"),
        "{}",
        stderr(&output)
    );
    fs::remove_dir_all(&directory).ok();
}

/// The verb's grammar is closed: only `verify <dir>`, and a malformed
/// invocation fails with exit code 2 before any path is opened.
#[test]
fn release_grammar_is_closed() {
    for arguments in [
        vec!["release"],
        vec!["release", "verify"],
        vec!["release", "sign", "dist"],
        vec!["release", "publish", "dist"],
        vec!["release", "verify", "dist", "extra"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_semaprax"))
            .args(&arguments)
            .output()
            .expect("the CLI must run");
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(
            stderr(&output).contains("release accepts exactly `verify <release-dir>`"),
            "{arguments:?}: {}",
            stderr(&output)
        );
    }
}
