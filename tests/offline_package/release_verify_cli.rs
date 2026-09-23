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
    ARCHIVE_PLATFORMS, DSSE_IN_TOTO_PAYLOAD_TYPE, IN_TOTO_STATEMENT_TYPE,
    SIGSTORE_BUNDLE_MEDIA_TYPE, SLSA_PROVENANCE_V1_PREDICATE_TYPE, TRUSTED_ISSUER,
    TRUSTED_REPOSITORY, TRUSTED_WORKFLOW_PATH,
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

/// Fabricated (not produced by any real signing operation) but base64-shaped
/// opaque signature/certificate material, matched between the message-
/// signature bundle below and a claim that consumes it. Reused verbatim from
/// `src/release_provenance/tests.rs`'s equivalent fixtures so the same
/// non-cryptographic material is recognizable across both test layers.
const FIXTURE_BUNDLE_SIGNATURE: &str = "RklYVFVSRS1TSUdTVE9SRS1TSUdOQVRVUkU=";
const FIXTURE_BUNDLE_CERTIFICATE: &str = "RklYVFVSRS1TSUdTVE9SRS1DRVJUSUZJQ0FURQ==";
const FIXTURE_ARCHIVE_ATTESTATION_CERTIFICATE: &str =
    "RklYVFVSRS1BVFRFU1RBVElPTi1DRVJUSUZJQ0FURQ==";
const FIXTURE_TRUSTED_ROOT: &str = "{\"trustedRoot\":\"fixture\"}\n";

/// A minimal standard (padded, `+`/`/`) base64 encoder, independent of any
/// crate dependency, sufficient for building small closed-shape Sigstore
/// bundle fixtures whose exact bytes this test controls.
fn standard_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[((first & 0x03) << 4 | second >> 4) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((second & 0x0f) << 2 | third >> 6) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

/// One closed-shape v0.3 verification-material block: one certificate and
/// one complete transparency-log entry of the given kind. Every byte field
/// is fabricated but canonical base64, so this satisfies the narrow
/// structural parser without being a real Rekor entry or a real certificate.
fn verification_material(kind: &str, certificate: &str) -> String {
    format!(
        r#"{{"certificate":{{"rawBytes":"{certificate}"}},"tlogEntries":[{{"logIndex":"1","logId":{{"keyId":"RklYVFVSRS1SRUtPUi1LRVk="}},"kindVersion":{{"kind":"{kind}","version":"0.0.1"}},"integratedTime":"1","inclusionPromise":{{"signedEntryTimestamp":"RklYVFVSRS1TRVQ="}},"inclusionProof":{{"logIndex":"1","rootHash":"RklYVFVSRS1ST09U","treeSize":"1","hashes":["RklYVFVSRS1IQVNI"],"checkpoint":{{"envelope":"fixture checkpoint"}}}},"canonicalizedBody":"RklYVFVSRS1SRUtPUi1CT0RZ"}}],"timestampVerificationData":{{"rfc3161Timestamps":[{{"signedTimestamp":"RklYVFVSRS1SRkMzMTYx"}}]}}}}"#
    )
}

/// A structurally admissible `cosign sign-blob` v0.3 message-signature
/// bundle over the exact `provenance_bytes`, whose declared digest is real
/// (so it binds to the claim and the provenance under test) but whose
/// signature and certificate are fabricated, not a real Sigstore signing
/// operation over that digest.
fn message_signature_bundle(provenance_bytes: &[u8], signature: &str, certificate: &str) -> String {
    let digest = sha256(provenance_bytes);
    let raw_digest = digest.strip_prefix("sha256:").unwrap();
    let digest_bytes: Vec<u8> = (0..raw_digest.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&raw_digest[offset..offset + 2], 16).unwrap())
        .collect();
    let encoded_digest = standard_base64(&digest_bytes);
    let material = verification_material("hashedrekord", certificate);
    format!(
        r#"{{"mediaType":"{SIGSTORE_BUNDLE_MEDIA_TYPE}","verificationMaterial":{material},"messageSignature":{{"messageDigest":{{"algorithm":"SHA2_256","digest":"{encoded_digest}"}},"signature":"{signature}"}}}}"#
    )
}

/// A `semaprax.release-signature-claim.v1` document that exactly consumes
/// `message_signature_bundle`'s fabricated signature/certificate strings, so
/// binding succeeds and only the cryptographic layer can still refuse it.
fn signed_claim_json(subject_digest: &str) -> String {
    let workflow_ref = format!("{TRUSTED_REPOSITORY}/{TRUSTED_WORKFLOW_PATH}@refs/tags/{TAG}");
    let subject = format!("repo:{TRUSTED_REPOSITORY}:ref:refs/tags/{TAG}");
    format!(
        r#"{{
  "schema": "semaprax.release-signature-claim.v1",
  "subject_digest": "{subject_digest}",
  "subject_name": "release-provenance.json",
  "identity": {{"issuer": "{TRUSTED_ISSUER}", "subject": "{subject}", "workflow_ref": "{workflow_ref}"}},
  "algorithm": "sigstore-cosign-bundle-v0.3",
  "signature": "{FIXTURE_BUNDLE_SIGNATURE}",
  "certificate": "{FIXTURE_BUNDLE_CERTIFICATE}"
}}"#
    )
}

/// The closed GitHub workflow-v1 producer predicate
/// `verify_archive_attestation_binds_release` requires, naming this test's
/// exact trusted repository, workflow path, tag, and commit.
fn github_artifact_predicate() -> String {
    format!(
        r#"{{"buildDefinition":{{"buildType":"https://actions.github.io/buildtypes/workflow/v1","externalParameters":{{"workflow":{{"path":"{TRUSTED_WORKFLOW_PATH}","ref":"refs/tags/{TAG}","repository":"https://github.com/{TRUSTED_REPOSITORY}"}}}},"internalParameters":{{"github":{{"event_name":"push","repository_id":"1","repository_owner_id":"1","runner_environment":"github-hosted"}}}},"resolvedDependencies":[{{"digest":{{"gitCommit":"{COMMIT}"}},"uri":"git+https://github.com/{TRUSTED_REPOSITORY}@refs/tags/{TAG}"}}]}},"runDetails":{{"builder":{{"id":"https://github.com/actions/runner/github-hosted"}},"metadata":{{"invocationId":"https://github.com/{TRUSTED_REPOSITORY}/actions/runs/1/attempts/1"}}}}}}"#
    )
}

/// A structurally admissible GitHub `actions/attest-build-provenance` DSSE
/// bundle whose one SLSA subject names the exact archive and its real
/// digest, but whose DSSE signature and certificate are fabricated.
fn archive_attestation_bundle(archive_name: &str, archive_bytes: &[u8]) -> String {
    let digest = sha256(archive_bytes);
    let raw_digest = digest.strip_prefix("sha256:").unwrap();
    let predicate = github_artifact_predicate();
    let statement = format!(
        r#"{{"_type":"{IN_TOTO_STATEMENT_TYPE}","subject":[{{"name":"{archive_name}","digest":{{"sha256":"{raw_digest}"}}}}],"predicateType":"{SLSA_PROVENANCE_V1_PREDICATE_TYPE}","predicate":{predicate}}}"#
    );
    let payload = standard_base64(statement.as_bytes());
    let material = verification_material("dsse", FIXTURE_ARCHIVE_ATTESTATION_CERTIFICATE);
    format!(
        r#"{{"mediaType":"{SIGSTORE_BUNDLE_MEDIA_TYPE}","verificationMaterial":{material},"dsseEnvelope":{{"payload":"{payload}","payloadType":"{DSSE_IN_TOTO_PAYLOAD_TYPE}","signatures":[{{"sig":"RklYVFVSRS1EU1NFLVNJR05BVFVSRQ=="}}]}}}}"#
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

/// Any signed-material marker selects the closed aggregate route. Incomplete
/// material must fail before either built-in cryptographic verification or
/// the unsigned, binding-only report path.
#[test]
fn release_verify_refuses_incomplete_offline_bundle_material() {
    let directory = release_directory("offline-material-without-capability");
    fs::write(
        directory.join("release-provenance.bundle"),
        b"untrusted fixture bundle",
    )
    .unwrap();

    let output = verify(&directory);
    assert_rejected(&output, "SPX-Z705");
    assert!(
        stderr(&output).contains("release-signature-claim.json"),
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

/// The standalone binary's default verifier for a complete offline bundle is
/// the real, network-free `SigstoreOfflineVerifier`, not a stub that accepts
/// anything shaped like a bundle. This directory is *structurally* complete
/// and self-consistent -- manifest, provenance, claim, message-signature
/// bundle, three archive attestations, and trusted root all bind to the same
/// exact bytes and pass every digest/identity check -- but its signature,
/// certificate, and transparency-log material are fabricated, never produced
/// by any real signing operation (this repository has none, per
/// `docs/RELEASE-SIGNING-POLICY-V1.md`). A correct build refuses this with
/// exactly the cryptographic-layer code `SPX-Z707`, proving the CLI actually
/// reaches the built-in cryptographic engine rather than silently treating a
/// complete-looking directory as `CRYPTOGRAPHICALLY VERIFIED OFFLINE`. A
/// defect that swapped in a no-op verifier, or that stopped calling it at
/// all, would instead print that success status or fail with an earlier
/// structural/binding code -- both of which this test rejects.
#[test]
fn release_verify_reaches_the_built_in_cryptographic_verifier_and_reports_spx_z707() {
    let directory = complete_offline_directory("crypto-engine-wiring");
    let output = verify(&directory);
    assert_rejected(&output, "SPX-Z707");
    let message = stderr(&output);
    assert!(
        !message.contains("CRYPTOGRAPHICALLY VERIFIED OFFLINE"),
        "{message}"
    );
    fs::remove_dir_all(&directory).ok();
}

// Complete structural material, deliberately not a signed SEMAPRAX release.
fn complete_offline_directory(label: &str) -> PathBuf {
    let directory = release_directory(label);
    let provenance = fs::read(directory.join("release-provenance.json")).unwrap();
    let subject_digest = sha256(&provenance);

    fs::write(
        directory.join("release-provenance.bundle"),
        message_signature_bundle(
            &provenance,
            FIXTURE_BUNDLE_SIGNATURE,
            FIXTURE_BUNDLE_CERTIFICATE,
        ),
    )
    .unwrap();
    fs::write(directory.join("trusted_root.jsonl"), FIXTURE_TRUSTED_ROOT).unwrap();
    fs::write(
        directory.join("release-signature-claim.json"),
        signed_claim_json(&subject_digest),
    )
    .unwrap();
    for platform in ARCHIVE_PLATFORMS {
        let name = archive_name(platform);
        let bytes = fs::read(directory.join(&name)).unwrap();
        fs::write(
            directory.join(format!("release-attestation-{platform}.json")),
            archive_attestation_bundle(&name, &bytes),
        )
        .unwrap();
    }

    directory
}

#[test]
fn doctor_release_real_cli_refuses_unsigned_swapped_stale_tampered_untrusted_material() {
    for (case, code) in [
        ("unsigned", "SPX-Z705"),
        ("fabricated-crypto", "SPX-Z707"),
        ("swapped", "SPX-Z702"),
        ("stale", "SPX-Z702"),
        ("tampered", "SPX-Z704"),
        ("untrusted-identity", "SPX-Z703"),
        ("untrusted-root", "SPX-Z707"),
        ("wrong-commitment", "SPX-Z707"),
    ] {
        let directory = if case == "unsigned" {
            release_directory("doctor-unsigned")
        } else {
            complete_offline_directory(&format!("doctor-{case}"))
        };
        match case {
            "swapped" => {
                let first =
                    directory.join(format!("release-attestation-{}.json", ARCHIVE_PLATFORMS[0]));
                let second =
                    directory.join(format!("release-attestation-{}.json", ARCHIVE_PLATFORMS[1]));
                let bytes = fs::read(&first).unwrap();
                fs::write(first, fs::read(&second).unwrap()).unwrap();
                fs::write(second, bytes).unwrap();
            }
            "stale" => {
                fs::write(
                    directory.join("release-signature-claim.json"),
                    signed_claim_json(FAKE_DIGEST),
                )
                .unwrap();
            }
            "tampered" => {
                let path = directory.join(archive_name(ARCHIVE_PLATFORMS[0]));
                let mut bytes = fs::read(&path).unwrap();
                bytes[0] ^= 1;
                fs::write(path, bytes).unwrap();
            }
            "untrusted-identity" => {
                let path = directory.join("release-signature-claim.json");
                let claim = fs::read_to_string(&path).unwrap();
                fs::write(
                    path,
                    claim.replace(TRUSTED_ISSUER, "https://untrusted.example"),
                )
                .unwrap();
            }
            "untrusted-root" => {
                let root: serde_json::Value = serde_json::from_str(include_str!(
                    "../fixtures/release_sigstore/public-good.json"
                ))
                .unwrap();
                let root = format!("{}\n", serde_json::to_string(&root).unwrap());
                sigstore_verify::trust_root::TrustedRoot::from_json(&root).unwrap();
                fs::write(directory.join("trusted_root.jsonl"), root).unwrap();
            }
            _ => {}
        }
        let before: Vec<_> = listing(&directory)
            .into_iter()
            .map(|name| {
                let bytes = fs::read(directory.join(&name)).unwrap();
                (name, bytes)
            })
            .collect();
        let output = Command::new(env!("CARGO_BIN_EXE_semaprax"))
            .args(["doctor", "verify-release"])
            .arg(&directory)
            .arg("--trusted-root-sha256")
            .arg(if case == "wrong-commitment" {
                "0".repeat(64)
            } else {
                // Independent test expectation: do not discover trust from
                // the release directory's mutable trusted_root.jsonl.
                sha256(FIXTURE_TRUSTED_ROOT.as_bytes())
                    .trim_start_matches("sha256:")
                    .to_owned()
            })
            .output()
            .unwrap();
        assert_rejected(&output, code);
        if matches!(case, "untrusted-root" | "wrong-commitment") {
            assert!(stderr(&output).contains("independently supplied SHA-256 commitment"));
        }
        let after: Vec<_> = listing(&directory)
            .into_iter()
            .map(|name| {
                let bytes = fs::read(directory.join(&name)).unwrap();
                (name, bytes)
            })
            .collect();
        assert_eq!(before, after, "doctor must not mutate {case} material");
        fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn doctor_release_real_cli_has_closed_grammar_and_scoped_help() {
    let uppercase = "A".repeat(64);
    for arguments in [
        vec!["doctor", "verify-release"],
        vec!["doctor", "verify-release", "dist"],
        vec!["doctor", "verify-release", ""],
        vec!["doctor", "verify-release", "--json"],
        vec!["doctor", "verify-release", "dist", "extra"],
        vec!["doctor", "verify-release", "dist", "--profile", "fixture"],
        vec!["doctor", "verify-release", "dist", "--trusted-root-sha256"],
        vec![
            "doctor",
            "verify-release",
            "dist",
            "--trusted-root-sha256",
            "0",
        ],
        vec![
            "doctor",
            "verify-release",
            "dist",
            "--trusted-root-sha256",
            &uppercase,
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_semaprax"))
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty());
        assert!(stderr(&output).contains("doctor accepts exactly `verify-release <release-dir> --trusted-root-sha256 <64-lowercase-hex>`"));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_semaprax"))
        .args(["doctor", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, b"Usage:\n  semaprax doctor [--profile <id>] [--target native|web|all] [--json]\n  semaprax doctor verify-release <release-dir> --trusted-root-sha256 <64-lowercase-hex>\n");
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
