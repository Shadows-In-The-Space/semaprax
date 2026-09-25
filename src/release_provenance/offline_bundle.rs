//! Closed Sigstore v0.3 framing and offline release aggregation.

use std::collections::BTreeMap;

use super::*;

pub const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const SLSA_PROVENANCE_V1_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
pub const DSSE_IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const MAX_SIGSTORE_BUNDLE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TRUSTED_ROOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_TRUSTED_ROOT_RECORDS: usize = 128;
const MAX_TLOG_ENTRIES: usize = 8;
const MAX_TLOG_HASHES: usize = 128;
const MAX_RFC3161_TIMESTAMPS: usize = 8;
const MAX_CHECKPOINT_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_PREDICATE_TEXT_BYTES: usize = 4096;
const MAX_PREDICATE_DEPENDENCIES: usize = 8;
const GITHUB_WORKFLOW_BUILD_TYPE: &str = "https://actions.github.io/buildtypes/workflow/v1";

fn bounded(bytes: &[u8], limit: usize, what: &str) -> Result<(), Diagnostic> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(shape_error(format!(
            "{what} must be non-empty and at most {limit} bytes"
        )));
    }
    Ok(())
}

fn base64(encoded: &str, what: &str, limit: usize) -> Result<Vec<u8>, Diagnostic> {
    fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let input = encoded.as_bytes();
    if input.is_empty() || input.len() % 4 != 0 {
        return Err(shape_error(format!(
            "{what} must be padded standard base64"
        )));
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for (index, chunk) in input.chunks_exact(4).enumerate() {
        let a = sextet(chunk[0])
            .ok_or_else(|| shape_error(format!("{what} is not standard base64")))?;
        let b = sextet(chunk[1])
            .ok_or_else(|| shape_error(format!("{what} is not standard base64")))?;
        let pad = match (chunk[2], chunk[3]) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            (b'=', _) => return Err(shape_error(format!("{what} has misplaced base64 padding"))),
            _ => 0,
        };
        if pad != 0 && index + 1 != input.len() / 4 {
            return Err(shape_error(format!("{what} has early base64 padding")));
        }
        let c = if pad == 2 {
            if b & 15 != 0 {
                return Err(shape_error(format!("{what} is not canonical base64")));
            }
            0
        } else {
            sextet(chunk[2]).ok_or_else(|| shape_error(format!("{what} is not standard base64")))?
        };
        let d = if pad == 0 {
            sextet(chunk[3]).ok_or_else(|| shape_error(format!("{what} is not standard base64")))?
        } else {
            if pad == 1 && c & 3 != 0 {
                return Err(shape_error(format!("{what} is not canonical base64")));
            }
            0
        };
        out.push((a << 2) | (b >> 4));
        if pad < 2 {
            out.push((b << 4) | (c >> 2));
        }
        if pad == 0 {
            out.push((c << 6) | d);
        }
        if out.len() > limit {
            return Err(shape_error(format!(
                "{what} exceeds the {limit}-byte limit"
            )));
        }
    }
    Ok(out)
}

fn decimal(value: &str, what: &str) -> Result<(), Diagnostic> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(shape_error(format!(
            "{what} must be a canonical unsigned decimal string"
        )));
    }
    if value.parse::<i64>().is_err() {
        return Err(shape_error(format!(
            "{what} must be a nonnegative i64 no greater than 9223372036854775807"
        )));
    }
    Ok(())
}

fn text<'a>(value: &'a Value, what: &str) -> Result<&'a str, Diagnostic> {
    let value = require_string(value, what)?;
    bounded(value.as_bytes(), MAX_PREDICATE_TEXT_BYTES, what)?;
    Ok(value)
}

fn git_commit(value: &Value, what: &str) -> Result<(), Diagnostic> {
    let value = text(value, what)?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(shape_error(format!(
            "{what} must be a 40-character lowercase hexadecimal git commit"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ParsedGithubArtifactPredicate {
    workflow_repository: String,
    workflow_path: String,
    workflow_ref: String,
    resolved_commits: Vec<String>,
}

fn github_artifact_predicate(value: &Value) -> Result<ParsedGithubArtifactPredicate, Diagnostic> {
    let predicate = object(value, "in-toto statement.predicate")?;
    check_exact_keys(
        predicate,
        &["buildDefinition", "runDetails"],
        "in-toto statement.predicate",
    )?;
    let definition = object(
        &value["buildDefinition"],
        "in-toto statement.predicate.buildDefinition",
    )?;
    check_exact_keys(
        definition,
        &[
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        ],
        "in-toto statement.predicate.buildDefinition",
    )?;
    if text(
        &value["buildDefinition"]["buildType"],
        "in-toto statement.predicate.buildDefinition.buildType",
    )? != GITHUB_WORKFLOW_BUILD_TYPE
    {
        return Err(shape_error(format!(
            "in-toto statement.predicate.buildDefinition.buildType must be {GITHUB_WORKFLOW_BUILD_TYPE}"
        )));
    }
    let external = object(
        &value["buildDefinition"]["externalParameters"],
        "in-toto statement.predicate.buildDefinition.externalParameters",
    )?;
    check_exact_keys(
        external,
        &["workflow"],
        "in-toto statement.predicate.buildDefinition.externalParameters",
    )?;
    let workflow = object(
        &value["buildDefinition"]["externalParameters"]["workflow"],
        "in-toto statement.predicate.buildDefinition.externalParameters.workflow",
    )?;
    check_exact_keys(
        workflow,
        &["path", "ref", "repository"],
        "in-toto statement.predicate.buildDefinition.externalParameters.workflow",
    )?;
    let workflow_path = text(
        &value["buildDefinition"]["externalParameters"]["workflow"]["path"],
        "in-toto statement.predicate.buildDefinition.externalParameters.workflow.path",
    )?
    .to_owned();
    let workflow_ref = text(
        &value["buildDefinition"]["externalParameters"]["workflow"]["ref"],
        "in-toto statement.predicate.buildDefinition.externalParameters.workflow.ref",
    )?
    .to_owned();
    let workflow_repository = text(
        &value["buildDefinition"]["externalParameters"]["workflow"]["repository"],
        "in-toto statement.predicate.buildDefinition.externalParameters.workflow.repository",
    )?
    .to_owned();
    let internal = object(
        &value["buildDefinition"]["internalParameters"],
        "in-toto statement.predicate.buildDefinition.internalParameters",
    )?;
    check_exact_keys(
        internal,
        &["github"],
        "in-toto statement.predicate.buildDefinition.internalParameters",
    )?;
    let github = object(
        &value["buildDefinition"]["internalParameters"]["github"],
        "in-toto statement.predicate.buildDefinition.internalParameters.github",
    )?;
    check_exact_keys(
        github,
        &[
            "event_name",
            "repository_id",
            "repository_owner_id",
            "runner_environment",
        ],
        "in-toto statement.predicate.buildDefinition.internalParameters.github",
    )?;
    text(
        &value["buildDefinition"]["internalParameters"]["github"]["event_name"],
        "in-toto statement.predicate.buildDefinition.internalParameters.github.event_name",
    )?;
    decimal(
        text(
            &value["buildDefinition"]["internalParameters"]["github"]["repository_id"],
            "in-toto statement.predicate.buildDefinition.internalParameters.github.repository_id",
        )?,
        "in-toto statement.predicate.buildDefinition.internalParameters.github.repository_id",
    )?;
    decimal(
        text(
            &value["buildDefinition"]["internalParameters"]["github"]["repository_owner_id"],
            "in-toto statement.predicate.buildDefinition.internalParameters.github.repository_owner_id",
        )?,
        "in-toto statement.predicate.buildDefinition.internalParameters.github.repository_owner_id",
    )?;
    if text(
        &value["buildDefinition"]["internalParameters"]["github"]["runner_environment"],
        "in-toto statement.predicate.buildDefinition.internalParameters.github.runner_environment",
    )? != "github-hosted"
    {
        return Err(shape_error(
            "in-toto statement.predicate internal runner must be github-hosted".to_owned(),
        ));
    }
    let dependencies = require_array(
        &value["buildDefinition"]["resolvedDependencies"],
        "in-toto statement.predicate.buildDefinition.resolvedDependencies",
    )?;
    if dependencies.is_empty() || dependencies.len() > MAX_PREDICATE_DEPENDENCIES {
        return Err(shape_error(format!(
            "in-toto statement.predicate.buildDefinition.resolvedDependencies must contain 1 through {MAX_PREDICATE_DEPENDENCIES} entries"
        )));
    }
    let mut resolved_commits = Vec::with_capacity(dependencies.len());
    for dependency in dependencies {
        let dependency = object(
            dependency,
            "in-toto statement.predicate.buildDefinition.resolvedDependencies[]",
        )?;
        check_exact_keys(
            dependency,
            &["digest", "uri"],
            "in-toto statement.predicate.buildDefinition.resolvedDependencies[]",
        )?;
        text(
            &dependency["uri"],
            "in-toto statement.predicate.buildDefinition.resolvedDependencies[].uri",
        )?;
        let digest = object(
            &dependency["digest"],
            "in-toto statement.predicate.buildDefinition.resolvedDependencies[].digest",
        )?;
        check_exact_keys(
            digest,
            &["gitCommit"],
            "in-toto statement.predicate.buildDefinition.resolvedDependencies[].digest",
        )?;
        let commit = text(
            &dependency["digest"]["gitCommit"],
            "in-toto statement.predicate.buildDefinition.resolvedDependencies[].digest.gitCommit",
        )?;
        git_commit(
            &dependency["digest"]["gitCommit"],
            "in-toto statement.predicate.buildDefinition.resolvedDependencies[].digest.gitCommit",
        )?;
        resolved_commits.push(commit.to_owned());
    }
    let details = object(
        &value["runDetails"],
        "in-toto statement.predicate.runDetails",
    )?;
    check_exact_keys(
        details,
        &["builder", "metadata"],
        "in-toto statement.predicate.runDetails",
    )?;
    let builder = object(
        &value["runDetails"]["builder"],
        "in-toto statement.predicate.runDetails.builder",
    )?;
    check_exact_keys(
        builder,
        &["id"],
        "in-toto statement.predicate.runDetails.builder",
    )?;
    text(
        &value["runDetails"]["builder"]["id"],
        "in-toto statement.predicate.runDetails.builder.id",
    )?;
    let metadata = object(
        &value["runDetails"]["metadata"],
        "in-toto statement.predicate.runDetails.metadata",
    )?;
    check_exact_keys(
        metadata,
        &["invocationId"],
        "in-toto statement.predicate.runDetails.metadata",
    )?;
    text(
        &value["runDetails"]["metadata"]["invocationId"],
        "in-toto statement.predicate.runDetails.metadata.invocationId",
    )?;
    Ok(ParsedGithubArtifactPredicate {
        workflow_repository,
        workflow_path,
        workflow_ref,
        resolved_commits,
    })
}

fn tlog_entry(value: &Value, expected_kind: &str) -> Result<(), Diagnostic> {
    let entry = object(value, "verificationMaterial.tlogEntries[]")?;
    check_exact_keys(
        entry,
        &[
            "canonicalizedBody",
            "integratedTime",
            "inclusionPromise",
            "inclusionProof",
            "kindVersion",
            "logId",
            "logIndex",
        ],
        "verificationMaterial.tlogEntries[]",
    )?;
    decimal(
        require_string(
            &value["logIndex"],
            "verificationMaterial.tlogEntries[].logIndex",
        )?,
        "verificationMaterial.tlogEntries[].logIndex",
    )?;
    let log_id = object(&value["logId"], "verificationMaterial.tlogEntries[].logId")?;
    check_exact_keys(
        log_id,
        &["keyId"],
        "verificationMaterial.tlogEntries[].logId",
    )?;
    base64(
        require_string(
            &value["logId"]["keyId"],
            "verificationMaterial.tlogEntries[].logId.keyId",
        )?,
        "verificationMaterial.tlogEntries[].logId.keyId",
        MAX_SIGSTORE_BUNDLE_BYTES,
    )?;
    let kind_version = object(
        &value["kindVersion"],
        "verificationMaterial.tlogEntries[].kindVersion",
    )?;
    check_exact_keys(
        kind_version,
        &["kind", "version"],
        "verificationMaterial.tlogEntries[].kindVersion",
    )?;
    if require_string(
        &value["kindVersion"]["kind"],
        "verificationMaterial.tlogEntries[].kindVersion.kind",
    )? != expected_kind
        || require_string(
            &value["kindVersion"]["version"],
            "verificationMaterial.tlogEntries[].kindVersion.version",
        )? != "0.0.1"
    {
        return Err(shape_error(format!(
            "verificationMaterial.tlogEntries[] must be {expected_kind} v0.0.1"
        )));
    }
    decimal(
        require_string(
            &value["integratedTime"],
            "verificationMaterial.tlogEntries[].integratedTime",
        )?,
        "verificationMaterial.tlogEntries[].integratedTime",
    )?;
    let promise = object(
        &value["inclusionPromise"],
        "verificationMaterial.tlogEntries[].inclusionPromise",
    )?;
    check_exact_keys(
        promise,
        &["signedEntryTimestamp"],
        "verificationMaterial.tlogEntries[].inclusionPromise",
    )?;
    base64(
        require_string(
            &value["inclusionPromise"]["signedEntryTimestamp"],
            "verificationMaterial.tlogEntries[].inclusionPromise.signedEntryTimestamp",
        )?,
        "verificationMaterial.tlogEntries[].inclusionPromise.signedEntryTimestamp",
        MAX_SIGSTORE_BUNDLE_BYTES,
    )?;
    let proof = object(
        &value["inclusionProof"],
        "verificationMaterial.tlogEntries[].inclusionProof",
    )?;
    check_exact_keys(
        proof,
        &["checkpoint", "hashes", "logIndex", "rootHash", "treeSize"],
        "verificationMaterial.tlogEntries[].inclusionProof",
    )?;
    decimal(
        require_string(
            &value["inclusionProof"]["logIndex"],
            "verificationMaterial.tlogEntries[].inclusionProof.logIndex",
        )?,
        "verificationMaterial.tlogEntries[].inclusionProof.logIndex",
    )?;
    decimal(
        require_string(
            &value["inclusionProof"]["treeSize"],
            "verificationMaterial.tlogEntries[].inclusionProof.treeSize",
        )?,
        "verificationMaterial.tlogEntries[].inclusionProof.treeSize",
    )?;
    base64(
        require_string(
            &value["inclusionProof"]["rootHash"],
            "verificationMaterial.tlogEntries[].inclusionProof.rootHash",
        )?,
        "verificationMaterial.tlogEntries[].inclusionProof.rootHash",
        MAX_SIGSTORE_BUNDLE_BYTES,
    )?;
    let hashes = require_array(
        &value["inclusionProof"]["hashes"],
        "verificationMaterial.tlogEntries[].inclusionProof.hashes",
    )?;
    if hashes.len() > MAX_TLOG_HASHES {
        return Err(shape_error(format!(
            "verificationMaterial.tlogEntries[].inclusionProof.hashes has more than {MAX_TLOG_HASHES} entries"
        )));
    }
    for hash in hashes {
        base64(
            require_string(
                hash,
                "verificationMaterial.tlogEntries[].inclusionProof.hashes[]",
            )?,
            "verificationMaterial.tlogEntries[].inclusionProof.hashes[]",
            MAX_SIGSTORE_BUNDLE_BYTES,
        )?;
    }
    let checkpoint = object(
        &value["inclusionProof"]["checkpoint"],
        "verificationMaterial.tlogEntries[].inclusionProof.checkpoint",
    )?;
    check_exact_keys(
        checkpoint,
        &["envelope"],
        "verificationMaterial.tlogEntries[].inclusionProof.checkpoint",
    )?;
    bounded(
        require_string(
            &value["inclusionProof"]["checkpoint"]["envelope"],
            "verificationMaterial.tlogEntries[].inclusionProof.checkpoint.envelope",
        )?
        .as_bytes(),
        MAX_CHECKPOINT_ENVELOPE_BYTES,
        "verificationMaterial.tlogEntries[].inclusionProof.checkpoint.envelope",
    )?;
    base64(
        require_string(
            &value["canonicalizedBody"],
            "verificationMaterial.tlogEntries[].canonicalizedBody",
        )?,
        "verificationMaterial.tlogEntries[].canonicalizedBody",
        MAX_SIGSTORE_BUNDLE_BYTES,
    )?;
    Ok(())
}

fn timestamps(value: &Value) -> Result<(), Diagnostic> {
    let timestamps = object(value, "verificationMaterial.timestampVerificationData")?;
    if timestamps.is_empty() {
        return Ok(());
    }
    check_exact_keys(
        timestamps,
        &["rfc3161Timestamps"],
        "verificationMaterial.timestampVerificationData",
    )?;
    let records = require_array(
        &value["rfc3161Timestamps"],
        "verificationMaterial.timestampVerificationData.rfc3161Timestamps",
    )?;
    if records.is_empty() || records.len() > MAX_RFC3161_TIMESTAMPS {
        return Err(shape_error(format!(
            "verificationMaterial.timestampVerificationData.rfc3161Timestamps must contain 1 through {MAX_RFC3161_TIMESTAMPS} records"
        )));
    }
    for record in records {
        let record = object(
            record,
            "verificationMaterial.timestampVerificationData.rfc3161Timestamps[]",
        )?;
        check_exact_keys(
            record,
            &["signedTimestamp"],
            "verificationMaterial.timestampVerificationData.rfc3161Timestamps[]",
        )?;
        base64(
            require_string(
                &record["signedTimestamp"],
                "verificationMaterial.timestampVerificationData.rfc3161Timestamps[].signedTimestamp",
            )?,
            "verificationMaterial.timestampVerificationData.rfc3161Timestamps[].signedTimestamp",
            MAX_SIGSTORE_BUNDLE_BYTES,
        )?;
    }
    Ok(())
}

fn material(value: &Value, what: &str, expected_kind: &str) -> Result<String, Diagnostic> {
    let map = object(value, what)?;
    check_exact_keys(
        map,
        &["certificate", "timestampVerificationData", "tlogEntries"],
        what,
    )?;
    let certificate = object(&value["certificate"], "verificationMaterial.certificate")?;
    check_exact_keys(
        certificate,
        &["rawBytes"],
        "verificationMaterial.certificate",
    )?;
    let raw = require_string(
        &value["certificate"]["rawBytes"],
        "verificationMaterial.certificate.rawBytes",
    )?;
    base64(
        raw,
        "verificationMaterial.certificate.rawBytes",
        MAX_SIGSTORE_BUNDLE_BYTES,
    )?;
    let entries = require_array(&value["tlogEntries"], "verificationMaterial.tlogEntries")?;
    if entries.is_empty() || entries.len() > MAX_TLOG_ENTRIES {
        return Err(shape_error(format!(
            "verificationMaterial.tlogEntries must contain 1 through {MAX_TLOG_ENTRIES} entries"
        )));
    }
    for entry in entries {
        tlog_entry(entry, expected_kind)?;
    }
    timestamps(&value["timestampVerificationData"])?;
    Ok(raw.to_owned())
}

#[derive(Debug, Clone)]
pub struct ParsedSigstoreMessageSignatureBundle {
    pub subject_digest: String,
    pub signature: String,
    pub certificate: String,
}

pub fn parse_sigstore_message_signature_bundle(
    bytes: &[u8],
) -> Result<ParsedSigstoreMessageSignatureBundle, Diagnostic> {
    bounded(
        bytes,
        MAX_SIGSTORE_BUNDLE_BYTES,
        "Sigstore message-signature bundle",
    )?;
    let value = parse_json(bytes, "Sigstore message-signature bundle")?;
    let map = object(&value, "Sigstore message-signature bundle")?;
    check_exact_keys(
        map,
        &["mediaType", "messageSignature", "verificationMaterial"],
        "Sigstore message-signature bundle",
    )?;
    if require_string(&value["mediaType"], "mediaType")? != SIGSTORE_BUNDLE_MEDIA_TYPE {
        return Err(shape_error(format!(
            "Sigstore bundle mediaType must be {SIGSTORE_BUNDLE_MEDIA_TYPE}"
        )));
    }
    let certificate = material(
        &value["verificationMaterial"],
        "verificationMaterial",
        "hashedrekord",
    )?;
    let signature = object(&value["messageSignature"], "messageSignature")?;
    check_exact_keys(
        signature,
        &["messageDigest", "signature"],
        "messageSignature",
    )?;
    let signature = require_string(
        &value["messageSignature"]["signature"],
        "messageSignature.signature",
    )?;
    base64(
        signature,
        "messageSignature.signature",
        MAX_SIGSTORE_BUNDLE_BYTES,
    )?;
    let digest = object(
        &value["messageSignature"]["messageDigest"],
        "messageSignature.messageDigest",
    )?;
    check_exact_keys(
        digest,
        &["algorithm", "digest"],
        "messageSignature.messageDigest",
    )?;
    if require_string(
        &value["messageSignature"]["messageDigest"]["algorithm"],
        "messageSignature.messageDigest.algorithm",
    )? != "SHA2_256"
    {
        return Err(shape_error(
            "messageSignature.messageDigest.algorithm must be SHA2_256".to_owned(),
        ));
    }
    let raw = base64(
        require_string(
            &value["messageSignature"]["messageDigest"]["digest"],
            "messageSignature.messageDigest.digest",
        )?,
        "messageSignature.messageDigest.digest",
        32,
    )?;
    if raw.len() != 32 {
        return Err(shape_error(
            "messageSignature.messageDigest.digest must decode to 32 bytes".to_owned(),
        ));
    }
    Ok(ParsedSigstoreMessageSignatureBundle {
        subject_digest: format!("sha256:{:x}", crate::digest_hex::LowerHex(raw)),
        signature: signature.to_owned(),
        certificate,
    })
}

#[derive(Debug, Clone)]
pub struct ParsedSigstoreArchiveAttestationBundle {
    pub archive_name: String,
    pub archive_digest: String,
    build: ParsedGithubArtifactPredicate,
}

pub fn parse_sigstore_archive_attestation_bundle(
    bytes: &[u8],
) -> Result<ParsedSigstoreArchiveAttestationBundle, Diagnostic> {
    bounded(
        bytes,
        MAX_SIGSTORE_BUNDLE_BYTES,
        "Sigstore archive-attestation bundle",
    )?;
    let value = parse_json(bytes, "Sigstore archive-attestation bundle")?;
    let map = object(&value, "Sigstore archive-attestation bundle")?;
    check_exact_keys(
        map,
        &["dsseEnvelope", "mediaType", "verificationMaterial"],
        "Sigstore archive-attestation bundle",
    )?;
    if require_string(&value["mediaType"], "mediaType")? != SIGSTORE_BUNDLE_MEDIA_TYPE {
        return Err(shape_error(format!(
            "Sigstore bundle mediaType must be {SIGSTORE_BUNDLE_MEDIA_TYPE}"
        )));
    }
    material(
        &value["verificationMaterial"],
        "verificationMaterial",
        "dsse",
    )?;
    let envelope = object(&value["dsseEnvelope"], "dsseEnvelope")?;
    check_exact_keys(
        envelope,
        &["payload", "payloadType", "signatures"],
        "dsseEnvelope",
    )?;
    if require_string(
        &value["dsseEnvelope"]["payloadType"],
        "dsseEnvelope.payloadType",
    )? != DSSE_IN_TOTO_PAYLOAD_TYPE
    {
        return Err(shape_error(format!(
            "dsseEnvelope.payloadType must be {DSSE_IN_TOTO_PAYLOAD_TYPE}"
        )));
    }
    let signatures = require_array(
        &value["dsseEnvelope"]["signatures"],
        "dsseEnvelope.signatures",
    )?;
    if signatures.len() != 1 {
        return Err(shape_error(
            "dsseEnvelope.signatures must contain exactly one signature".to_owned(),
        ));
    }
    let signature = object(&signatures[0], "dsseEnvelope.signatures[]")?;
    check_exact_keys(signature, &["sig"], "dsseEnvelope.signatures[]")?;
    base64(
        require_string(&signatures[0]["sig"], "dsseEnvelope.signatures[].sig")?,
        "dsseEnvelope.signatures[].sig",
        MAX_SIGSTORE_BUNDLE_BYTES,
    )?;
    let statement = parse_json(
        &base64(
            require_string(&value["dsseEnvelope"]["payload"], "dsseEnvelope.payload")?,
            "dsseEnvelope.payload",
            MAX_SIGSTORE_BUNDLE_BYTES,
        )?,
        "in-toto statement",
    )?;
    let map = object(&statement, "in-toto statement")?;
    check_exact_keys(
        map,
        &["_type", "predicate", "predicateType", "subject"],
        "in-toto statement",
    )?;
    if require_string(&statement["_type"], "in-toto statement._type")? != IN_TOTO_STATEMENT_TYPE
        || require_string(
            &statement["predicateType"],
            "in-toto statement.predicateType",
        )? != SLSA_PROVENANCE_V1_PREDICATE_TYPE
    {
        return Err(shape_error(
            "in-toto statement has an unadmitted type".to_owned(),
        ));
    }
    let build = github_artifact_predicate(&statement["predicate"])?;
    let subjects = require_array(&statement["subject"], "in-toto statement.subject")?;
    if subjects.len() != 1 {
        return Err(shape_error(
            "in-toto statement.subject must contain exactly one archive subject".to_owned(),
        ));
    }
    let subject = object(&subjects[0], "in-toto statement.subject[]")?;
    check_exact_keys(subject, &["digest", "name"], "in-toto statement.subject[]")?;
    let name = require_string(&subjects[0]["name"], "in-toto statement.subject[].name")?;
    let digest = object(&subjects[0]["digest"], "in-toto statement.subject[].digest")?;
    check_exact_keys(digest, &["sha256"], "in-toto statement.subject[].digest")?;
    let digest = require_string(
        &subjects[0]["digest"]["sha256"],
        "in-toto statement.subject[].digest.sha256",
    )?;
    if name.is_empty()
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(shape_error(
            "in-toto statement archive subject is malformed".to_owned(),
        ));
    }
    Ok(ParsedSigstoreArchiveAttestationBundle {
        archive_name: name.to_owned(),
        archive_digest: format!("sha256:{digest}"),
        build,
    })
}

#[derive(Debug, Clone)]
pub struct ParsedSigstoreTrustedRoot {
    pub digest: String,
    pub record_count: usize,
}

pub fn parse_sigstore_trusted_root_jsonl(
    bytes: &[u8],
) -> Result<ParsedSigstoreTrustedRoot, Diagnostic> {
    bounded(
        bytes,
        MAX_TRUSTED_ROOT_BYTES,
        "Sigstore trusted-root package",
    )?;
    let text = std::str::from_utf8(bytes)
        .map_err(|e| shape_error(format!("Sigstore trusted-root package is not UTF-8: {e}")))?;
    if !text.ends_with('\n') {
        return Err(shape_error(
            "Sigstore trusted-root package must be newline-terminated JSONL".to_owned(),
        ));
    }
    let mut records = 0usize;
    for line in text.split_terminator('\n') {
        if line.is_empty() || line.ends_with('\r') {
            return Err(shape_error(
                "Sigstore trusted-root package has a blank or CRLF record".to_owned(),
            ));
        }
        object(
            &parse_json(line.as_bytes(), "Sigstore trusted-root package record")?,
            "Sigstore trusted-root package record",
        )?;
        records += 1;
        if records > MAX_TRUSTED_ROOT_RECORDS {
            return Err(shape_error(format!(
                "Sigstore trusted-root package has more than {MAX_TRUSTED_ROOT_RECORDS} records"
            )));
        }
    }
    if records == 0 {
        return Err(shape_error(
            "Sigstore trusted-root package must have a record".to_owned(),
        ));
    }
    Ok(ParsedSigstoreTrustedRoot {
        digest: sha256_digest(bytes),
        record_count: records,
    })
}

pub fn verify_archive_attestation_binds_manifest(
    manifest_bytes: &[u8],
    name: &str,
    bytes: &[u8],
    bundle_bytes: &[u8],
) -> Result<(), Diagnostic> {
    let manifest = parse_manifest(manifest_bytes)?;
    let artifact = manifest
        .artifacts
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| {
            artifact_error(format!(
                "archive {name:?} is not named by the release manifest"
            ))
        })?;
    if bytes.len() as u64 != artifact.size || sha256_digest(bytes) != artifact.digest {
        return Err(artifact_error(format!(
            "archive {name:?} disagrees with its manifest size or digest"
        )));
    }
    let bundle = parse_sigstore_archive_attestation_bundle(bundle_bytes)?;
    if bundle.archive_name != artifact.name || bundle.archive_digest != artifact.digest {
        return Err(binding_error(
            "archive-attestation subject disagrees with its manifest archive".to_owned(),
        ));
    }
    Ok(())
}

/// Bind one archive attestation's producer identity to the exact release
/// statement before a caller-supplied cryptographic verifier receives it.
/// The lower-level manifest function above remains useful for per-archive
/// integrity checks; aggregate verification additionally rejects a structurally
/// valid attestation replayed from another repository, workflow, tag, or
/// source commit.
pub fn verify_archive_attestation_binds_release(
    manifest_bytes: &[u8],
    provenance_bytes: &[u8],
    name: &str,
    bytes: &[u8],
    bundle_bytes: &[u8],
) -> Result<(), Diagnostic> {
    verify_provenance_binds_manifest(provenance_bytes, manifest_bytes)?;
    let manifest = parse_manifest(manifest_bytes)?;
    let provenance = parse_provenance(provenance_bytes)?;
    let artifact = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == name)
        .ok_or_else(|| {
            artifact_error(format!(
                "archive {name:?} is not named by the release manifest"
            ))
        })?;
    if bytes.len() as u64 != artifact.size || sha256_digest(bytes) != artifact.digest {
        return Err(artifact_error(format!(
            "archive {name:?} disagrees with its manifest size or digest"
        )));
    }
    let bundle = parse_sigstore_archive_attestation_bundle(bundle_bytes)?;
    if bundle.archive_name != artifact.name || bundle.archive_digest != artifact.digest {
        return Err(binding_error(
            "archive-attestation subject disagrees with its manifest archive".to_owned(),
        ));
    }

    let expected_repository = format!("https://github.com/{TRUSTED_REPOSITORY}");
    let expected_ref = format!("refs/tags/{}", provenance.tag);
    if bundle.build.workflow_repository != expected_repository
        || bundle.build.workflow_path != TRUSTED_WORKFLOW_PATH
        || bundle.build.workflow_ref != expected_ref
    {
        return Err(identity_error(
            "archive-attestation workflow identity does not match the trusted release repository, workflow, and exact tag"
                .to_owned(),
        ));
    }
    if !bundle
        .build
        .resolved_commits
        .iter()
        .any(|commit| commit == &provenance.commit)
    {
        return Err(binding_error(
            "archive-attestation resolved dependencies do not include the exact release commit"
                .to_owned(),
        ));
    }
    Ok(())
}

pub fn verify_signature_claim_consumes_sigstore_bundle(
    claim_bytes: &[u8],
    provenance_bytes: &[u8],
    bundle_bytes: &[u8],
) -> Result<(), Diagnostic> {
    verify_signature_claim_binds_provenance(claim_bytes, provenance_bytes)?;
    let claim = parse_signature_claim(claim_bytes)?;
    let bundle = parse_sigstore_message_signature_bundle(bundle_bytes)?;
    if bundle.subject_digest != sha256_digest(provenance_bytes)
        || bundle.signature != claim.signature
        || bundle.certificate != claim.certificate
    {
        return Err(binding_error(
            "signature claim does not exactly consume its Sigstore bundle".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedReleaseIdentity {
    pub issuer: String,
    pub repository: String,
    pub workflow_path: String,
    pub tag: String,
    pub subject: String,
    pub workflow_ref: String,
}

pub(super) fn expected_release_identity(
    manifest_bytes: &[u8],
    provenance_bytes: &[u8],
) -> Result<ExpectedReleaseIdentity, Diagnostic> {
    let manifest = parse_manifest(manifest_bytes)?;
    let provenance = parse_provenance(provenance_bytes)?;
    if manifest.tag != provenance.tag || provenance.source_repository != TRUSTED_REPOSITORY {
        return Err(binding_error(
            "cannot derive a trusted release identity from unbound manifest/provenance bytes"
                .to_owned(),
        ));
    }
    let tag = provenance.tag;
    Ok(ExpectedReleaseIdentity {
        issuer: TRUSTED_ISSUER.to_owned(),
        repository: TRUSTED_REPOSITORY.to_owned(),
        workflow_path: TRUSTED_WORKFLOW_PATH.to_owned(),
        subject: format!("{TRUSTED_OIDC_SUBJECT_PREFIX}:ref:refs/tags/{tag}"),
        workflow_ref: format!("{TRUSTED_REPOSITORY}/{TRUSTED_WORKFLOW_PATH}@refs/tags/{tag}"),
        tag,
    })
}

pub trait OfflineBundleVerificationCapability {
    fn verify_offline_bundle(
        &self,
        expected_identity: &ExpectedReleaseIdentity,
        subject_bytes: &[u8],
        bundle_bytes: &[u8],
        trusted_root_bytes: &[u8],
    ) -> Result<(), Diagnostic>;
}
pub struct OfflineReleaseArchive<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
    pub attestation_bundle_bytes: &'a [u8],
}

pub fn verify_offline_release_with_capability(
    manifest_bytes: &[u8],
    provenance_bytes: &[u8],
    claim_bytes: &[u8],
    message_bundle: &[u8],
    root: &[u8],
    archives: &[OfflineReleaseArchive<'_>],
    capability: &dyn OfflineBundleVerificationCapability,
) -> Result<(), Diagnostic> {
    verify_release_binding(manifest_bytes, provenance_bytes, claim_bytes)?;
    verify_signature_claim_consumes_sigstore_bundle(claim_bytes, provenance_bytes, message_bundle)?;
    parse_sigstore_trusted_root_jsonl(root)?;
    let manifest = parse_manifest(manifest_bytes)?;
    if archives.len() != manifest.artifacts.len() {
        return Err(artifact_error(
            "offline archive inventory count disagrees with manifest".to_owned(),
        ));
    }
    let mut supplied = BTreeMap::new();
    for archive in archives {
        if archive.name.is_empty() || supplied.insert(archive.name, archive).is_some() {
            return Err(artifact_error(
                "offline archive inventory has an empty or repeated name".to_owned(),
            ));
        }
    }
    for artifact in &manifest.artifacts {
        let archive = supplied.get(artifact.name.as_str()).ok_or_else(|| {
            artifact_error(format!(
                "offline archive inventory is missing {:?}",
                artifact.name
            ))
        })?;
        verify_archive_attestation_binds_release(
            manifest_bytes,
            provenance_bytes,
            archive.name,
            archive.bytes,
            archive.attestation_bundle_bytes,
        )?;
    }
    let identity = expected_release_identity(manifest_bytes, provenance_bytes)?;
    capability.verify_offline_bundle(&identity, provenance_bytes, message_bundle, root)?;
    for artifact in &manifest.artifacts {
        let archive = supplied
            .get(artifact.name.as_str())
            .expect("checked before capability invocation");
        capability.verify_offline_bundle(
            &identity,
            archive.bytes,
            archive.attestation_bundle_bytes,
            root,
        )?;
    }
    Ok(())
}

pub fn verify_archive_attestation_with_offline_capability(
    manifest: &[u8],
    provenance: &[u8],
    claim: &[u8],
    name: &str,
    bytes: &[u8],
    bundle: &[u8],
    root: &[u8],
    capability: &dyn OfflineBundleVerificationCapability,
) -> Result<(), Diagnostic> {
    verify_release_binding(manifest, provenance, claim)?;
    verify_archive_attestation_binds_release(manifest, provenance, name, bytes, bundle)?;
    parse_sigstore_trusted_root_jsonl(root)?;
    capability.verify_offline_bundle(
        &expected_release_identity(manifest, provenance)?,
        bytes,
        bundle,
        root,
    )
}
pub fn verify_signature_claim_with_offline_capability(
    manifest: &[u8],
    claim: &[u8],
    provenance: &[u8],
    bundle: &[u8],
    root: &[u8],
    capability: &dyn OfflineBundleVerificationCapability,
) -> Result<(), Diagnostic> {
    verify_release_binding(manifest, provenance, claim)?;
    verify_signature_claim_consumes_sigstore_bundle(claim, provenance, bundle)?;
    parse_sigstore_trusted_root_jsonl(root)?;
    capability.verify_offline_bundle(
        &expected_release_identity(manifest, provenance)?,
        provenance,
        bundle,
        root,
    )
}
