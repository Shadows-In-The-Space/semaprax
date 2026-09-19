//! `semaprax release verify <release-dir>`: issue #168's one documented
//! command over an already-downloaded release directory.
//!
//! This front adds **no verification of its own**. It locates the three
//! documents `docs/RELEASE-SIGNING-POLICY-V1.md` names, then hands their
//! exact bytes to `semaprax::release_provenance`, the independent decoder
//! and binding verifier that owns every rule. Everything is re-derived from
//! what is on disk: the manifest digest is recomputed from the manifest's
//! real bytes, each named archive is re-hashed from its real bytes, and a
//! signature claim's subject digest is recomputed from the provenance
//! statement's real bytes. Nothing the documents say about themselves is
//! trusted.
//!
//! The command carries no authority. It opens only the exact paths the
//! manifest names (no directory listing, no traversal), never touches the
//! network, never spawns a process, and never executes a release artifact --
//! `release_provenance`'s own
//! `verification_touches_no_network_and_executes_no_artifact` states that
//! property for the verifier, and this adapter preserves it. It publishes
//! nothing, signs nothing, and creates no key or identity material.
//!
//! **No SEMAPRAX release is signed today** and no signing key or keyless
//! identity exists for this repository, so a successful run reports
//! `VERIFIED UNSIGNED RELEASE` -- a successful verification of an *unsigned*
//! release, never evidence that one was signed. Even when a
//! `semaprax.release-signature-claim.v1` document is present, this command
//! verifies only its *binding* (subject digest and pinned trusted identity);
//! its `signature`/`certificate` bytes are never decoded or cryptographically
//! checked, so the status stays `VERIFIED UNSIGNED RELEASE` either way.

use std::path::{Path, PathBuf};

use semaprax::diagnostic::Diagnostic;
use semaprax::release_provenance::{
    parse_manifest, verify_manifest_artifacts_on_disk, verify_provenance_binds_manifest,
    verify_signature_claim_binds_provenance,
};

const USAGE: &str = "release accepts exactly `verify <release-dir>`; see `semaprax help release`";

/// The three document names a published release directory carries, exactly
/// as `docs/RELEASE-SIGNING-POLICY-V1.md` spells them.
pub(crate) const MANIFEST_FILE: &str = "release-manifest.json";
pub(crate) const PROVENANCE_FILE: &str = "release-provenance.json";
pub(crate) const SIGNATURE_CLAIM_FILE: &str = "release-signature-claim.json";

/// Largest release *document* this front reads. The real documents are a few
/// kilobytes; this bound only keeps a hostile directory from being read into
/// memory before the owning verifier ever sees it. Release *archives* are not
/// read here at all -- `verify_manifest_artifacts_on_disk` re-hashes those.
const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;

/// This front's own code, for "the release directory does not present a
/// readable document at all". Every *verification* failure keeps the owning
/// module's code instead (SPX-Z701 shape, SPX-Z702 binding, SPX-Z703
/// identity, SPX-Z704 artifact), because this front decides none of them.
fn document_error(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z705", message)
}

/// `release verify <dir>` and nothing else. An unknown subcommand, a missing
/// operand, an extra operand, or an option-shaped operand fails closed with
/// the usage line and exit code 2 before any path is opened.
pub(crate) fn parse(args: &[String]) -> Result<PathBuf, u8> {
    let rejected = match args {
        [subcommand, directory]
            if subcommand == "verify" && !directory.is_empty() && !directory.starts_with('-') =>
        {
            return Ok(PathBuf::from(directory));
        }
        [subcommand, ..] if subcommand != "verify" => {
            format!("unknown release subcommand `{subcommand}`; {USAGE}")
        }
        _ => USAGE.to_owned(),
    };
    eprintln!("{rejected}");
    Err(2)
}

/// Read one release document from the directory, bounded, failing closed if
/// it is absent, unreadable, or larger than [`MAX_DOCUMENT_BYTES`].
fn read_document(directory: &Path, name: &str) -> Result<Vec<u8>, Diagnostic> {
    let path = directory.join(name);
    let metadata = std::fs::metadata(&path).map_err(|error| {
        document_error(format!(
            "release directory {} does not contain a readable {name}: {error}",
            directory.display()
        ))
    })?;
    if metadata.len() > MAX_DOCUMENT_BYTES {
        return Err(document_error(format!(
            "{name} is {} bytes, over the {MAX_DOCUMENT_BYTES}-byte bound for a release document",
            metadata.len()
        )));
    }
    std::fs::read(&path)
        .map_err(|error| document_error(format!("cannot read {}: {error}", path.display())))
}

/// What the directory says about signing. A missing claim document is the
/// ordinary case today and is *not* an error; any other read failure is.
fn signature_lines(directory: &Path, provenance_bytes: &[u8]) -> Result<String, Diagnostic> {
    let path = directory.join(SIGNATURE_CLAIM_FILE);
    match std::fs::metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(format!(
            "signature: absent; this directory carries no {SIGNATURE_CLAIM_FILE}\n"
        )),
        Err(error) => Err(document_error(format!(
            "cannot inspect {}: {error}",
            path.display()
        ))),
        Ok(_) => {
            let claim_bytes = read_document(directory, SIGNATURE_CLAIM_FILE)?;
            verify_signature_claim_binds_provenance(&claim_bytes, provenance_bytes)?;
            Ok(format!(
                "signature: {SIGNATURE_CLAIM_FILE} binds these exact provenance bytes and names \
                 the pinned trusted identity\n\
                 signature: binding only; its signature and certificate bytes were NOT decoded or \
                 cryptographically verified\n"
            ))
        }
    }
}

/// The nonclaims every run prints, signed or not. Kept one constant so the
/// two status paths cannot drift on what was and was not established.
const NONCLAIMS: &str = "\
Verified: integrity (the bytes on disk are the bytes the manifest and the\n\
provenance statement recorded) and provenance binding (version, tag, commit,\n\
builder workflow identity, and the complete artifact inventory agree).\n\
Not verified and not claimed: authenticity. No cryptographic signature is\n\
checked by this command, this repository holds no signing key or keyless\n\
identity, and no SEMAPRAX release is signed today. Reproducibility,\n\
notarization, and production support are separate claims this command does\n\
not make. Nothing was published, signed, executed, or installed.\n";

/// Verify one release directory and render its deterministic report.
pub(crate) fn run(directory: &Path) -> Result<String, Diagnostic> {
    let manifest_bytes = read_document(directory, MANIFEST_FILE)?;
    let provenance_bytes = read_document(directory, PROVENANCE_FILE)?;

    // The owning module decides every rule below; this front only orders the
    // checks and stops at the first failure.
    verify_provenance_binds_manifest(&provenance_bytes, &manifest_bytes)?;
    verify_manifest_artifacts_on_disk(&manifest_bytes, directory)?;
    let signature = signature_lines(directory, &provenance_bytes)?;

    // Re-parsed, not carried out of the checks above: the report names only
    // fields an independent decode of the same bytes produced.
    let manifest = parse_manifest(&manifest_bytes)?;
    let artifacts = manifest.artifacts.len();
    Ok(format!(
        "release verify: {directory}\n\
         manifest: {MANIFEST_FILE} (version {version}, tag {tag}, commit {commit})\n\
         provenance: {PROVENANCE_FILE} binds this manifest byte for byte\n\
         artifacts: {artifacts} of {artifacts} re-hashed from disk; every size and digest matches \
         the manifest\n\
         {signature}\
         status: VERIFIED UNSIGNED RELEASE\n\
         {NONCLAIMS}",
        directory = directory.display(),
        version = manifest.version,
        tag = manifest.tag,
        commit = manifest.commit,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parse_admits_only_verify_with_exactly_one_directory() {
        assert_eq!(
            parse(&strings(&["verify", "dist"])).unwrap(),
            PathBuf::from("dist")
        );
        for malformed in [
            &[][..],
            &["verify"][..],
            &["verify", "dist", "extra"][..],
            &["verify", ""][..],
            &["verify", "--json"][..],
            &["sign", "dist"][..],
            &["publish", "dist"][..],
        ] {
            assert_eq!(parse(&strings(malformed)), Err(2), "{malformed:?}");
        }
    }

    /// A missing directory fails closed with this front's own code, never
    /// with a verifier code -- nothing was verified.
    #[test]
    fn a_directory_without_a_manifest_fails_closed_before_any_verification() {
        let directory = std::env::temp_dir().join(format!(
            "semaprax-release-verify-absent-{}",
            std::process::id()
        ));
        let error = run(&directory).expect_err("an absent release directory must fail closed");
        assert_eq!(error.code, "SPX-Z705");
        assert!(error.message.contains(MANIFEST_FILE), "{}", error.message);
    }

    /// The nonclaims can never read as a signed release.
    #[test]
    fn the_report_template_never_claims_a_signature() {
        assert!(NONCLAIMS.contains("no SEMAPRAX release is signed today"));
        assert!(NONCLAIMS.contains("Not verified and not claimed: authenticity."));
    }
}
