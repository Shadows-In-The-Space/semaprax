//! Canonical, deterministic rendering for
//! `semaprax.lean-export-coverage.v1` and
//! `semaprax.lean-proof-certificate.v1`.
//!
//! Both follow the repository's existing `{schema,digest,bytes,payload}`
//! envelope convention (see
//! `crate::assurance_manifest::proof_certificate::render`) with their own
//! domain-separation strings, so neither becomes byte-coupled to another
//! module's rendering choices. Rendering uses plain `format!`, not the
//! budgeted formatter: these are artifacts whose bytes are *bound* by
//! digest, so a silently truncated render under an ambient output budget
//! would be a determinism bug, not a nicety.

use sha2::{Digest as _, Sha256};

use crate::diagnostic::quote_json;

use super::lean::{ExportedObligation, ModuleExport, ASSUMPTIONS, EXPORT_SCHEMA, NAMESPACE};
use super::profile::{Excluded, PROFILE_V1};

pub const COVERAGE_SCHEMA: &str = "semaprax.lean-export-coverage.v1";
pub const CERTIFICATE_SCHEMA: &str = "semaprax.lean-proof-certificate.v1";

/// The one compiled-artifact target a certificate binds, matching the
/// already-shipped SMT certificate's choice: the Wasm core module is a real
/// compiled binary produced in-process, with no external toolchain and no
/// ambient authority. No native artifact is bound — native codegen emits
/// C11 source text that still needs an external C toolchain this crate does
/// not invoke.
pub const ARTIFACT_TARGET: &str = "wasm-core-module-v1";

const COVERAGE_PAYLOAD_DOMAIN: &[u8] = b"semaprax.lean-export-coverage.payload.v1\0";
const SOURCE_DIGEST_DOMAIN: &[u8] = b"semaprax.lean-proof-certificate.source.v1\0";
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"semaprax.lean-proof-certificate.payload.v1\0";
const LEAN_DIGEST_DOMAIN: &[u8] = b"semaprax.lean-proof-certificate.lean.v1\0";
const ARTIFACT_DIGEST_DOMAIN: &[u8] = b"semaprax.lean-proof-certificate.artifact.v1\0";

/// Everything a reader must be told this certificate does *not* claim.
const NONCLAIMS_JSON: &str = "\"kernel_checked_covers_only_the_listed_obligations_of_the_listed_declaration\",\
\"declarations_listed_under_unsupported_are_not_proved_and_not_claimed\",\
\"no_assurance_manifest_merge\",\
\"no_program_root_binding_this_export_binds_a_single_file_semantic_revision_not_a_managed_workspace_program_root\",\
\"artifact_binding_covers_only_the_wasm_core_module_target_no_native_artifact_bound\",\
\"artifact_binding_does_not_by_itself_prove_the_backend_lowering_preserves_the_source_theorem\",\
\"translation_from_semaprax_to_lean_is_trusted_and_unverified\",\
\"requires_clauses_are_assumed_not_proved\",\
\"no_target_execution_and_no_project_test_discovery\",\
\"not_human_approval_or_policy\",\
\"not_signature_or_publication_authority\",\
\"kernel_evidence_is_local_host_only_hosted_ci_provisions_no_lean_toolchain\",\
\"read_only_no_source_changes\"";

pub fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    )
}

pub fn source_digest(source: &str) -> String {
    domain_digest(SOURCE_DIGEST_DOMAIN, source.as_bytes())
}

pub fn payload_digest(payload: &[u8]) -> String {
    domain_digest(PAYLOAD_DIGEST_DOMAIN, payload)
}

pub fn lean_digest(lean_source: &str) -> String {
    domain_digest(LEAN_DIGEST_DOMAIN, lean_source.as_bytes())
}

pub fn artifact_digest(bytes: &[u8]) -> String {
    domain_digest(ARTIFACT_DIGEST_DOMAIN, bytes)
}

fn json_array(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}

fn assumptions_json() -> String {
    json_array(
        &ASSUMPTIONS
            .iter()
            .map(|(id, text)| {
                format!(
                    "{{\"id\":{},\"text\":{}}}",
                    quote_json(id),
                    quote_json(text)
                )
            })
            .collect::<Vec<_>>(),
    )
}

fn unsupported_json(unsupported: &[(String, String, Excluded)]) -> String {
    json_array(
        &unsupported
            .iter()
            .map(|(id, name, reason)| {
                format!(
                    "{{\"declaration_id\":{},\"name\":{},\"code\":{},\"detail\":{}}}",
                    quote_json(id),
                    quote_json(name),
                    quote_json(reason.code()),
                    quote_json(&reason.detail())
                )
            })
            .collect::<Vec<_>>(),
    )
}

fn obligation_json(
    declaration_id: &str,
    obligation: &ExportedObligation,
    axioms: Option<&[String]>,
) -> String {
    let ensures_index = obligation
        .ensures_index
        .map_or_else(|| "null".to_owned(), |index| index.to_string());
    let axioms_json = axioms.map_or_else(
        || "null".to_owned(),
        |list| json_array(&list.iter().map(|name| quote_json(name)).collect::<Vec<_>>()),
    );
    format!(
        "{{\"declaration_id\":{},\"obligation_id\":{},\"theorem_name\":{},\"kind\":{},\
\"ensures_index\":{ensures_index},\"origin\":{},\"axioms\":{axioms_json}}}",
        quote_json(declaration_id),
        quote_json(&obligation.obligation_id),
        quote_json(&format!("{NAMESPACE}.{}", obligation.theorem_name)),
        quote_json(obligation.kind),
        quote_json(&obligation.origin),
    )
}

/// Render the whole-module coverage report: what was exported, what was
/// refused and why, and every assumption the translation introduces. This
/// is the artifact that makes "silently skipped a construct" impossible to
/// do accidentally — a declaration is in exactly one of the two lists.
#[must_use]
pub fn render_coverage(export: &ModuleExport) -> String {
    let exported = json_array(
        &export
            .exported
            .iter()
            .map(|function| {
                let obligations = json_array(
                    &function
                        .obligations
                        .iter()
                        .map(|obligation| {
                            obligation_json(&function.declaration_id, obligation, None)
                        })
                        .collect::<Vec<_>>(),
                );
                format!(
                    "{{\"declaration_id\":{},\"name\":{},\"obligations\":{obligations}}}",
                    quote_json(&function.declaration_id),
                    quote_json(&function.name),
                )
            })
            .collect::<Vec<_>>(),
    );
    let payload = format!(
        "{{\"schema\":\"{COVERAGE_SCHEMA}\",\"export_schema\":\"{EXPORT_SCHEMA}\",\
\"module\":{},\"revision\":{},\"profile\":{},\"lean_source_sha256\":{},\
\"exported\":{exported},\"unsupported\":{},\"assumptions\":{},\"nonclaims\":[{NONCLAIMS_JSON}]}}",
        quote_json(&export.module),
        quote_json(&export.revision),
        quote_json(PROFILE_V1),
        quote_json(&lean_digest(&export.lean_source)),
        unsupported_json(&export.unsupported),
        assumptions_json(),
    );
    format!(
        "{{\"schema\":\"{COVERAGE_SCHEMA}\",\"digest\":{},\"bytes\":{},\"payload\":{payload}}}",
        quote_json(&domain_digest(COVERAGE_PAYLOAD_DOMAIN, payload.as_bytes())),
        payload.len(),
    )
}

/// Every field [`render_certificate`] needs, as one struct so no caller can
/// pass them positionally out of order.
pub struct CertificateInput<'a> {
    pub source_path_text: &'a str,
    pub source_sha256: &'a str,
    pub export: &'a ModuleExport,
    pub declaration_id: &'a str,
    pub ensures_index: usize,
    pub obligation_id: &'a str,
    pub theorem_name: &'a str,
    pub compiler_version: &'a str,
    pub toolchain: &'a str,
    pub axioms: &'a [(String, Vec<String>)],
    pub artifact_sha256: &'a str,
    pub artifact_bytes: usize,
}

/// Render one certificate for one kernel-checked postcondition obligation.
///
/// The whole generated Lean document is embedded verbatim (like the SMT
/// certificate embeds its SMT-LIB2 script), so a third party can hand it to
/// their own Lean 4 toolchain without trusting this exporter; the digest
/// bindings then let them confirm it is the document this exact source
/// produces.
#[must_use]
pub fn render_certificate(input: &CertificateInput<'_>) -> String {
    let axiom_for = |qualified: &str| -> Option<&[String]> {
        input
            .axioms
            .iter()
            .find(|(name, _)| name == qualified)
            .map(|(_, list)| list.as_slice())
    };
    let obligations = json_array(
        &input
            .export
            .exported
            .iter()
            .flat_map(|function| {
                function.obligations.iter().map(move |obligation| {
                    let qualified = format!("{NAMESPACE}.{}", obligation.theorem_name);
                    obligation_json(&function.declaration_id, obligation, axiom_for(&qualified))
                })
            })
            .collect::<Vec<_>>(),
    );
    let source_json = format!(
        "{{\"path\":{},\"revision\":{},\"sha256\":{}}}",
        quote_json(input.source_path_text),
        quote_json(&input.export.revision),
        quote_json(input.source_sha256),
    );
    let kernel_json = format!(
        "{{\"identity\":{},\"toolchain\":{},\"standard_axioms\":{}}}",
        quote_json(super::kernel_report::KERNEL_IDENTITY),
        quote_json(input.toolchain),
        json_array(
            &super::kernel_report::STANDARD_AXIOMS
                .iter()
                .map(|name| quote_json(name))
                .collect::<Vec<_>>()
        ),
    );
    let artifact_json = format!(
        "{{\"target\":{},\"bytes\":{},\"sha256\":{}}}",
        quote_json(ARTIFACT_TARGET),
        input.artifact_bytes,
        quote_json(input.artifact_sha256),
    );
    let payload = format!(
        "{{\"schema\":\"{CERTIFICATE_SCHEMA}\",\"export_schema\":\"{EXPORT_SCHEMA}\",\
\"source\":{source_json},\"module\":{},\"declaration_id\":{},\"obligation_id\":{},\
\"ensures_index\":{},\"theorem_name\":{},\"profile\":{},\"compiler_version\":{},\
\"kernel\":{kernel_json},\"artifact\":{artifact_json},\"lean_source\":{},\
\"lean_source_sha256\":{},\"obligations\":{obligations},\"assumptions\":{},\
\"unsupported\":{},\"verdict\":\"kernel_checked\",\"nonclaims\":[{NONCLAIMS_JSON}]}}",
        quote_json(&input.export.module),
        quote_json(input.declaration_id),
        quote_json(input.obligation_id),
        input.ensures_index,
        quote_json(input.theorem_name),
        quote_json(PROFILE_V1),
        quote_json(input.compiler_version),
        quote_json(&input.export.lean_source),
        quote_json(&lean_digest(&input.export.lean_source)),
        assumptions_json(),
        unsupported_json(&input.export.unsupported),
    );
    format!(
        "{{\"schema\":\"{CERTIFICATE_SCHEMA}\",\"digest\":{},\"bytes\":{},\"payload\":{payload}}}",
        quote_json(&payload_digest(payload.as_bytes())),
        payload.len(),
    )
}
