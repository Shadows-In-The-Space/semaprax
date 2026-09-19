//! Canonical, hand-written JSON rendering for the four files an OCI Image
//! Layout needs. Every value embedded here has already passed
//! [`super::validation`], whose closed charsets exclude `"`, `\`, and every
//! control byte, so no JSON string escaping is required; renderers still
//! never accept a value they have not validated, so a future charset
//! widening cannot reopen an injection.

use sha2::{Digest, Sha256};

use super::OciPlan;

pub const MEDIA_TYPE_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const MEDIA_TYPE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const MEDIA_TYPE_CONFIG: &str = "application/vnd.semaprax.oci-deployable.config.v1+json";
pub const MEDIA_TYPE_WASM_LAYER: &str =
    "application/vnd.semaprax.oci-deployable.wasm-module.v1+wasm";
pub const ARTIFACT_TYPE: &str = "application/vnd.semaprax.oci-deployable.v1+json";
pub(crate) const OCI_LAYOUT_VERSION: &str = "1.0.0";

/// The `oci-layout` marker file. Fixed bytes: no field ever varies.
pub(crate) fn oci_layout_bytes() -> Vec<u8> {
    format!("{{\"imageLayoutVersion\":\"{OCI_LAYOUT_VERSION}\"}}\n").into_bytes()
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

pub(crate) fn sha256_digest_fact(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// The SEMAPRAX-owned config blob. This is not an OCI image config (it
/// carries no `os`/`architecture`/`created`/`rootfs`): the manifest's
/// `artifactType` marks this whole object as a SEMAPRAX OCI deployable
/// artifact rather than a runnable OCI image, so a generic tool must not
/// interpret this blob as an OCI Image Configuration.
pub(crate) fn render_config(plan: &OciPlan, wasm_sha256: &str) -> Vec<u8> {
    format!(
        "{{\"schema\":\"semaprax.oci-deployable.config.v1\",\
\"project\":\"{project}\",\
\"project_revision\":\"{project_revision}\",\
\"workspace_revision\":\"{workspace_revision}\",\
\"project_graph_digest\":\"{project_graph_digest}\",\
\"entry_module\":\"{entry_module}\",\
\"content\":{{\"kind\":\"wasm-module\",\"media_type\":\"{wasm_media_type}\",\"bytes\":{wasm_bytes},\"sha256\":\"{wasm_sha256}\"}},\
\"nonclaims\":[\"not_a_runnable_container_image\",\"no_base_layer\",\"no_operating_system_rootfs\",\"unsigned\",\"not_published\"]}}",
        project = plan.project_name,
        project_revision = plan.project_revision,
        workspace_revision = plan.workspace_revision,
        project_graph_digest = plan.project_graph_digest,
        entry_module = plan.entry_module,
        wasm_media_type = MEDIA_TYPE_WASM_LAYER,
        wasm_bytes = plan.wasm_bytes.len(),
    )
    .into_bytes()
}

/// The OCI Image Manifest referencing the config blob and the single Wasm
/// content layer. No base layer is listed: OCI artifacts do not require
/// one, and this compiler never fetches, resolves, or names a base image --
/// see `docs/OCI-DEPLOYABLE-ARTIFACT-V1.md` for why.
pub(crate) fn render_manifest(
    plan: &OciPlan,
    config_digest: &str,
    config_len: usize,
    layer_digest: &str,
    layer_len: usize,
) -> Vec<u8> {
    format!(
        "{{\"schemaVersion\":2,\
\"mediaType\":\"{manifest_media_type}\",\
\"artifactType\":\"{artifact_type}\",\
\"config\":{{\"mediaType\":\"{config_media_type}\",\"digest\":\"{config_digest}\",\"size\":{config_len}}},\
\"layers\":[{{\"mediaType\":\"{wasm_media_type}\",\"digest\":\"{layer_digest}\",\"size\":{layer_len}}}],\
\"annotations\":{{\
\"io.semaprax.project\":\"{project}\",\
\"io.semaprax.project.revision\":\"{project_revision}\",\
\"io.semaprax.workspace.revision\":\"{workspace_revision}\",\
\"io.semaprax.project.graph-digest\":\"{project_graph_digest}\",\
\"io.semaprax.entry-module\":\"{entry_module}\",\
\"org.opencontainers.image.title\":\"{project}.wasm\"}}}}",
        manifest_media_type = MEDIA_TYPE_MANIFEST,
        artifact_type = ARTIFACT_TYPE,
        config_media_type = MEDIA_TYPE_CONFIG,
        wasm_media_type = MEDIA_TYPE_WASM_LAYER,
        project = plan.project_name,
        project_revision = plan.project_revision,
        workspace_revision = plan.workspace_revision,
        project_graph_digest = plan.project_graph_digest,
        entry_module = plan.entry_module,
    )
    .into_bytes()
}

/// The OCI Image Layout index, naming the one manifest above by digest.
pub(crate) fn render_index(plan: &OciPlan, manifest_digest: &str, manifest_len: usize) -> Vec<u8> {
    format!(
        "{{\"schemaVersion\":2,\
\"mediaType\":\"{index_media_type}\",\
\"manifests\":[{{\"mediaType\":\"{manifest_media_type}\",\"artifactType\":\"{artifact_type}\",\"digest\":\"{manifest_digest}\",\"size\":{manifest_len},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"{project}\"}}}}]}}",
        index_media_type = MEDIA_TYPE_INDEX,
        manifest_media_type = MEDIA_TYPE_MANIFEST,
        artifact_type = ARTIFACT_TYPE,
        project = plan.project_name,
    )
    .into_bytes()
}
