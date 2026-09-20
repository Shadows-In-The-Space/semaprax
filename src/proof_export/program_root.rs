//! Additive ProgramRoot association for one existing Lean proof certificate.
//!
//! The original `semaprax.lean-proof-certificate.v1` remains a single-file
//! wire: changing it would invalidate independently stored certificates and
//! make its narrower scope ambiguous. This module instead emits a small,
//! separately replayable association which binds those exact certificate
//! bytes to one retained Project's exact ProgramRoot and one source row in
//! that ProgramRoot's source projection.
//!
//! No function here opens a Project, runs Lean, or performs target execution.
//! A caller supplies an already retained [`crate::project::ProjectRevision`]
//! and any kernel remains the explicit [`super::LeanKernel`] capability.

use std::path::Path;

use serde_json::Value;

use crate::assurance_manifest::{AssuranceClass, MethodRecord, VerifiedProjectProof};
use crate::diagnostic::Diagnostic;
use crate::project::{ProgramRoot, ProjectRevision, PROGRAM_ROOT_SCHEMA};

use super::certificate::domain_digest;
use super::kernel_report::{KERNEL_IDENTITY, PINNED_TOOLCHAIN};
use super::verify::{
    rebind_certificate_against_source_text, verify_certificate, verify_kernel_replay,
    CheckedCertificate,
};
use super::{CERTIFICATE_SCHEMA, PROFILE_V1};

/// The additive wire carrying an exact ProgramRoot association for one v1
/// Lean certificate. It does not replace or extend the certificate wire.
pub const PROGRAM_ROOT_BINDING_SCHEMA: &str = "semaprax.lean-proof-program-root-binding.v1";

const PAYLOAD_DOMAIN: &[u8] = b"semaprax.lean-proof-program-root-binding.payload.v1\0";
const CERTIFICATE_DOMAIN: &[u8] = b"semaprax.lean-proof-program-root-binding.certificate.v1\0";
const PROGRAM_ROOT_BYTES_DOMAIN: &[u8] =
    b"semaprax.lean-proof-program-root-binding.program-root.v1\0";

const NONCLAIMS: [&str; 8] = [
    "additive_association_does_not_change_lean_proof_certificate_v1",
    "kernel_checked_covers_only_the_exact_certificate_obligations",
    "program_root_binding_does_not_prove_backend_lowering_preserves_the_source_theorem",
    "translation_from_semaprax_to_lean_is_trusted_and_unverified",
    "requires_clauses_are_assumed_not_proved",
    "no_target_execution_or_project_test_discovery",
    "no_process_filesystem_network_or_tool_discovery_authority",
    "not_execution_publication_signing_or_candidate_acceptance_authority",
];

/// A structurally valid association, extracted once for exact Project replay
/// and for an Assurance Manifest method reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedProgramRootBinding {
    pub binding_digest: String,
    pub certificate_digest: String,
    pub certificate_bytes: u64,
    pub program_root: String,
    pub program_root_bytes: u64,
    pub program_root_sha256: String,
    pub source_path: String,
    pub source_revision: String,
    pub source_digest: String,
}

fn consistency_error(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z111", message)
}

fn drift_error(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z112", message)
}

fn is_sha256_wire_form(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn require_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, Diagnostic> {
    value
        .as_str()
        .ok_or_else(|| consistency_error(format!("`{field}` must be a string")))
}

fn object_keys(value: &Value, context: &str) -> Result<Vec<String>, Diagnostic> {
    value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .ok_or_else(|| consistency_error(format!("{context} must be a JSON object")))
}

fn check_exact_keys(
    mut found: Vec<String>,
    expected: &[&str],
    context: &str,
) -> Result<(), Diagnostic> {
    found.sort();
    let mut expected_sorted = expected.to_vec();
    expected_sorted.sort_unstable();
    if found
        .iter()
        .map(String::as_str)
        .ne(expected_sorted.iter().copied())
    {
        return Err(consistency_error(format!(
            "{context} keys must be exactly {expected_sorted:?}, found {found:?}"
        )));
    }
    Ok(())
}

fn json_array(items: &[&str]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|item| crate::diagnostic::quote_json(item))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn certificate_digest(certificate: &str) -> String {
    domain_digest(CERTIFICATE_DOMAIN, certificate.as_bytes())
}

fn program_root_bytes_digest(program_root: &ProgramRoot) -> String {
    domain_digest(PROGRAM_ROOT_BYTES_DOMAIN, program_root.to_json().as_bytes())
}

fn payload_slice<'a>(binding: &'a str) -> Result<&'a str, Diagnostic> {
    const PAYLOAD_KEY: &str = "\"payload\":";
    let offset = binding.find(PAYLOAD_KEY).ok_or_else(|| {
        consistency_error("ProgramRoot binding is missing its payload member".to_owned())
    })?;
    if !binding.ends_with('}') {
        return Err(consistency_error(
            "ProgramRoot binding must end with `}`".to_owned(),
        ));
    }
    let payload = &binding[offset + PAYLOAD_KEY.len()..binding.len() - 1];
    if !payload.starts_with('{') || !payload.ends_with('}') {
        return Err(consistency_error(
            "ProgramRoot binding payload must be a JSON object".to_owned(),
        ));
    }
    Ok(payload)
}

fn project_error(errors: Vec<Diagnostic>, context: &str) -> Diagnostic {
    let detail = errors.first().map_or_else(
        || "unknown Project replay failure".to_owned(),
        |error| error.message.clone(),
    );
    drift_error(format!("{context}: {detail}"))
}

fn source_for<'a>(
    revision: &'a ProjectRevision,
    source_path: &str,
) -> Result<&'a crate::project::ProjectSource, Diagnostic> {
    revision
        .sources()
        .iter()
        .find(|source| source.path() == source_path)
        .ok_or_else(|| {
            drift_error(
                "ProgramRoot binding source.path is not a source in the retained Project"
                    .to_owned(),
            )
        })
}

/// Bind exact certificate bytes to a source row and derived ProgramRoot of an
/// already retained Project revision. This does not run a kernel; callers
/// must have obtained the certificate through an explicit kernel capability.
pub fn bind_certificate_to_program_root(
    certificate: &str,
    revision: &ProjectRevision,
    source_path: &str,
) -> Result<String, Diagnostic> {
    let checked = verify_certificate_against_project_source(certificate, revision, source_path)?;
    let source = source_for(revision, source_path)?;
    let workspace = revision
        .canonical_workspace_revision()
        .map_err(|errors| project_error(errors, "cannot derive canonical workspace revision"))?;
    let root = workspace
        .program_root()
        .map_err(|errors| project_error(errors, "cannot derive ProgramRoot"))?;
    let certificate_json = format!(
        "{{\"schema\":{},\"bytes\":{},\"sha256\":{}}}",
        crate::diagnostic::quote_json(CERTIFICATE_SCHEMA),
        certificate.len(),
        crate::diagnostic::quote_json(&certificate_digest(certificate)),
    );
    let root_json = format!(
        "{{\"schema\":{},\"program_root\":{},\"bytes\":{},\"sha256\":{}}}",
        crate::diagnostic::quote_json(PROGRAM_ROOT_SCHEMA),
        crate::diagnostic::quote_json(root.program_root()),
        root.to_json().len(),
        crate::diagnostic::quote_json(&program_root_bytes_digest(&root)),
    );
    let source_json = format!(
        "{{\"path\":{},\"revision\":{},\"sha256\":{}}}",
        crate::diagnostic::quote_json(source.path()),
        crate::diagnostic::quote_json(source.source_revision()),
        crate::diagnostic::quote_json(source.source_digest()),
    );
    let payload = format!(
        "{{\"schema\":\"{PROGRAM_ROOT_BINDING_SCHEMA}\",\"certificate\":{certificate_json},\
\"program_root\":{root_json},\"source\":{source_json},\"nonclaims\":{}}}",
        json_array(&NONCLAIMS),
    );
    let rendered = format!(
        "{{\"schema\":\"{PROGRAM_ROOT_BINDING_SCHEMA}\",\"digest\":{},\"bytes\":{},\"payload\":{payload}}}",
        crate::diagnostic::quote_json(&domain_digest(PAYLOAD_DOMAIN, payload.as_bytes())),
        payload.len(),
    );
    // Keep this apparent use non-accidental: the exact certificate replay
    // above verifies its semantic/artifact chain before any association is
    // rendered, while the binding itself carries only public fixed fields.
    let _ = checked;
    Ok(rendered)
}

/// Verify the association's closed wire and exact connection to the supplied
/// certificate. This does not reopen source bytes or derive a Project root.
pub fn verify_program_root_binding(
    binding: &str,
    certificate: &str,
) -> Result<CheckedProgramRootBinding, Diagnostic> {
    verify_certificate(certificate)?;
    let value: Value = serde_json::from_str(binding).map_err(|error| {
        consistency_error(format!("ProgramRoot binding is not valid JSON: {error}"))
    })?;
    check_exact_keys(
        object_keys(&value, "ProgramRoot binding")?,
        &["bytes", "digest", "payload", "schema"],
        "ProgramRoot binding",
    )?;
    if value["schema"].as_str() != Some(PROGRAM_ROOT_BINDING_SCHEMA) {
        return Err(consistency_error(format!(
            "ProgramRoot binding schema must be {PROGRAM_ROOT_BINDING_SCHEMA}"
        )));
    }
    let payload = payload_slice(binding)?;
    let digest = require_string(&value["digest"], "digest")?;
    if !is_sha256_wire_form(digest) || digest != domain_digest(PAYLOAD_DOMAIN, payload.as_bytes()) {
        return Err(consistency_error(
            "ProgramRoot binding digest does not match its exact payload bytes".to_owned(),
        ));
    }
    if value["bytes"].as_u64() != Some(payload.len() as u64) {
        return Err(consistency_error(
            "ProgramRoot binding bytes do not match its exact payload bytes".to_owned(),
        ));
    }
    let payload_value: Value = serde_json::from_str(payload).map_err(|error| {
        consistency_error(format!(
            "ProgramRoot binding payload is not valid JSON: {error}"
        ))
    })?;
    check_exact_keys(
        object_keys(&payload_value, "ProgramRoot binding payload")?,
        &[
            "certificate",
            "nonclaims",
            "program_root",
            "schema",
            "source",
        ],
        "ProgramRoot binding payload",
    )?;
    if payload_value["schema"].as_str() != Some(PROGRAM_ROOT_BINDING_SCHEMA) {
        return Err(consistency_error(
            "ProgramRoot binding payload schema is unsupported".to_owned(),
        ));
    }
    let nonclaims = payload_value["nonclaims"].as_array().ok_or_else(|| {
        consistency_error("ProgramRoot binding nonclaims must be an array".to_owned())
    })?;
    if nonclaims.len() != NONCLAIMS.len()
        || nonclaims
            .iter()
            .zip(NONCLAIMS)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(consistency_error(
            "ProgramRoot binding nonclaims do not match the exact v1 vocabulary".to_owned(),
        ));
    }

    let certificate_value = &payload_value["certificate"];
    check_exact_keys(
        object_keys(certificate_value, "ProgramRoot binding certificate")?,
        &["bytes", "schema", "sha256"],
        "ProgramRoot binding certificate",
    )?;
    if certificate_value["schema"].as_str() != Some(CERTIFICATE_SCHEMA) {
        return Err(consistency_error(
            "ProgramRoot binding references an unsupported certificate schema".to_owned(),
        ));
    }
    let certificate_bytes = certificate_value["bytes"].as_u64().ok_or_else(|| {
        consistency_error(
            "ProgramRoot binding certificate.bytes must be an unsigned integer".to_owned(),
        )
    })?;
    let certificate_digest_value =
        require_string(&certificate_value["sha256"], "certificate.sha256")?.to_owned();
    if !is_sha256_wire_form(&certificate_digest_value)
        || certificate_bytes != certificate.len() as u64
        || certificate_digest_value != certificate_digest(certificate)
    {
        return Err(drift_error(
            "ProgramRoot binding does not authenticate the supplied exact certificate bytes"
                .to_owned(),
        ));
    }

    let root_value = &payload_value["program_root"];
    check_exact_keys(
        object_keys(root_value, "ProgramRoot binding program_root")?,
        &["bytes", "program_root", "schema", "sha256"],
        "ProgramRoot binding program_root",
    )?;
    if root_value["schema"].as_str() != Some(PROGRAM_ROOT_SCHEMA) {
        return Err(consistency_error(
            "ProgramRoot binding references an unsupported ProgramRoot schema".to_owned(),
        ));
    }
    let program_root =
        require_string(&root_value["program_root"], "program_root.program_root")?.to_owned();
    let program_root_sha256 =
        require_string(&root_value["sha256"], "program_root.sha256")?.to_owned();
    let program_root_bytes = root_value["bytes"].as_u64().ok_or_else(|| {
        consistency_error(
            "ProgramRoot binding program_root.bytes must be an unsigned integer".to_owned(),
        )
    })?;
    if !is_sha256_wire_form(&program_root) || !is_sha256_wire_form(&program_root_sha256) {
        return Err(consistency_error(
            "ProgramRoot binding root identities must use sha256 wire form".to_owned(),
        ));
    }

    let source_value = &payload_value["source"];
    check_exact_keys(
        object_keys(source_value, "ProgramRoot binding source")?,
        &["path", "revision", "sha256"],
        "ProgramRoot binding source",
    )?;
    let source_path = require_string(&source_value["path"], "source.path")?.to_owned();
    let source_revision = require_string(&source_value["revision"], "source.revision")?.to_owned();
    let source_digest = require_string(&source_value["sha256"], "source.sha256")?.to_owned();
    if source_path.is_empty()
        || !is_sha256_wire_form(&source_revision)
        || !is_sha256_wire_form(&source_digest)
    {
        return Err(consistency_error(
            "ProgramRoot binding source facts are malformed".to_owned(),
        ));
    }
    Ok(CheckedProgramRootBinding {
        binding_digest: digest.to_owned(),
        certificate_digest: certificate_digest_value,
        certificate_bytes,
        program_root,
        program_root_bytes,
        program_root_sha256,
        source_path,
        source_revision,
        source_digest,
    })
}

/// Rebind a certificate to source held by one retained Project revision. This
/// is the in-memory equivalent of source-path replay: no raw filesystem
/// lookup is performed after the Project has been retained.
pub fn verify_certificate_against_project_source(
    certificate: &str,
    revision: &ProjectRevision,
    source_path: &str,
) -> Result<CheckedCertificate, Diagnostic> {
    let source = source_for(revision, source_path)?;
    let (checked, _, _) = rebind_certificate_against_source_text(
        certificate,
        source.source(),
        Path::new(source.path()),
    )?;
    if checked.revision != source.source_revision() {
        return Err(drift_error(
            "certificate semantic revision does not match the retained Project source row"
                .to_owned(),
        ));
    }
    Ok(checked)
}

fn rebind_certificate_against_project_program_root(
    certificate: &str,
    binding: &str,
    revision: &ProjectRevision,
) -> Result<
    (
        CheckedCertificate,
        super::ModuleExport,
        Vec<(String, Vec<String>)>,
        CheckedProgramRootBinding,
    ),
    Diagnostic,
> {
    let checked_binding = verify_program_root_binding(binding, certificate)?;
    let source = source_for(revision, &checked_binding.source_path)?;
    if source.source_revision() != checked_binding.source_revision
        || source.source_digest() != checked_binding.source_digest
    {
        return Err(drift_error(
            "ProgramRoot binding source facts do not match the retained Project source row"
                .to_owned(),
        ));
    }
    let (checked, export, axioms) = rebind_certificate_against_source_text(
        certificate,
        source.source(),
        Path::new(source.path()),
    )?;
    if checked.revision != checked_binding.source_revision {
        return Err(drift_error(
            "certificate semantic revision does not match the ProgramRoot binding source row"
                .to_owned(),
        ));
    }
    let workspace = revision
        .canonical_workspace_revision()
        .map_err(|errors| project_error(errors, "cannot rederive canonical workspace revision"))?;
    let root = workspace
        .program_root()
        .map_err(|errors| project_error(errors, "cannot rederive ProgramRoot"))?;
    if root.program_root() != checked_binding.program_root
        || root.to_json().len() as u64 != checked_binding.program_root_bytes
        || program_root_bytes_digest(&root) != checked_binding.program_root_sha256
    {
        return Err(drift_error(
            "ProgramRoot binding does not match the retained Project's exact ProgramRoot bytes"
                .to_owned(),
        ));
    }
    Ok((checked, export, axioms, checked_binding))
}

/// Verify every structural, source, compiler, artifact and exact ProgramRoot
/// association. No external kernel is called by this route.
pub fn verify_certificate_against_program_root(
    certificate: &str,
    binding: &str,
    revision: &ProjectRevision,
) -> Result<CheckedCertificate, Diagnostic> {
    rebind_certificate_against_project_program_root(certificate, binding, revision)
        .map(|(checked, _, _, _)| checked)
}

/// Verify ProgramRoot association and every certificate binding before the
/// caller-supplied Lean kernel sees any bytes.
pub fn verify_certificate_with_kernel_against_program_root(
    certificate: &str,
    binding: &str,
    revision: &ProjectRevision,
    kernel: &dyn super::LeanKernel,
) -> Result<CheckedCertificate, Diagnostic> {
    let (checked, export, axioms, _) =
        rebind_certificate_against_project_program_root(certificate, binding, revision)?;
    verify_kernel_replay(checked, export, axioms, kernel)
}

/// Produce opaque evidence for one exact Project assurance postcondition only
/// after an explicit caller-supplied Lean kernel has confirmed the bound
/// certificate. The token cannot be constructed or retargeted outside this
/// crate, and Project assurance independently rechecks its exact retained
/// Project revision, ProgramRoot, source row and certificate association.
///
/// Checked arithmetic range obligations remain proof-chain prerequisites, not
/// separately promoted Assurance Manifest obligations.
pub fn assurance_method_attachment(
    certificate: &str,
    binding: &str,
    revision: &ProjectRevision,
    kernel: &dyn super::LeanKernel,
) -> Result<VerifiedProjectProof, Diagnostic> {
    let checked = verify_certificate_with_kernel_against_program_root(
        certificate,
        binding,
        revision,
        kernel,
    )?;
    let association = verify_program_root_binding(binding, certificate)?;
    let method = MethodRecord {
        runtime_fallback: true,
        target: Some("wasm-core-module-v1".to_owned()),
        proof_ref: Some(association.binding_digest.clone()),
        artifact_digest: Some(checked.artifact_sha256.clone()),
        bounds: Some(format!(
            "{PROFILE_V1}; exact certificate and ProgramRoot association replayed"
        )),
        inputs: vec![
            association.certificate_digest.clone(),
            association.program_root.clone(),
            association.source_revision.clone(),
            association.source_digest.clone(),
        ],
        detail: Some(
            "Pinned Lean kernel evidence is bound to this exact retained Project ProgramRoot, \
             source row, compiler and Wasm core-module artifact. It proves only the selected \
             postcondition under the certificate's explicit assumptions; it does not prove \
             lowering preservation or grant execution, publication or acceptance authority."
                .to_owned(),
        ),
        ..MethodRecord::new(
            AssuranceClass::TheoremProved,
            KERNEL_IDENTITY,
            PINNED_TOOLCHAIN,
        )
    };
    Ok(VerifiedProjectProof::kernel_confirmed(
        checked.obligation_id,
        checked.declaration_id,
        method,
        revision.project_revision().to_owned(),
        association.program_root,
        association.source_path,
        association.source_revision,
        association.source_digest,
        association.certificate_digest,
    ))
}
