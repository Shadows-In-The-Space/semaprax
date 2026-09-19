//! Deterministic, offline OCI Image Layout emitter for one checked SEMAPRAX
//! project's already-compiled, already-verified deterministic Wasm module.
//!
//! This crate deliberately knows nothing about SEMAPRAX HIR, Project
//! manifests, or the compiler's descriptor/replay machinery. Its input is
//! exactly the caller-authenticated identity and Wasm bytes; see
//! `src/project/oci.rs` in the main crate for the glue that extracts those
//! from a `ProjectWebBuild` envelope. This split mirrors
//! `semaprax-native-rust-owned-data-package`: a lower, dependency-inverted
//! packaging crate that neither compiles nor trusts anything it was not
//! itself handed.
//!
//! ## What this is, and is not
//!
//! The emitted directory is a structurally valid OCI Image Layout (an
//! `oci-layout` marker, an `index.json`, and content-addressed blobs). It is
//! an *OCI artifact*, not a runnable *OCI image*: there is no base layer, no
//! operating-system root filesystem, no entrypoint/cmd process metadata, and
//! the config blob is a SEMAPRAX-owned JSON document rather than an OCI
//! Image Configuration. See `docs/OCI-DEPLOYABLE-ARTIFACT-V1.md` for why no
//! base image is ever fetched, resolved, or named, and for exactly what a
//! human or a separate deployment pipeline must still supply to turn this
//! into something a container runtime can execute.
//!
//! This crate has no registry client, no network code, and no `--publish`
//! path of any kind: [`build_and_publish`] writes one local directory and
//! nothing else. It also refuses to run at all if a container-registry
//! credential-shaped environment variable is present -- see
//! [`validation::refuse_if_credential_environment_present`].
#![forbid(unsafe_code)]

mod publish;
mod render;
mod validation;

/// Hard ceiling on the Wasm module this crate will package. Matches the
/// compiler's own `MAX_PROJECT_WEB_BUILD_BYTES` order of magnitude; this
/// crate does not compile Wasm, so it only needs a sane upper bound against
/// a hostile or corrupted caller, not the compiler's exact limit.
pub const MAX_WASM_BYTES: usize = 16 * 1024 * 1024;

pub use render::{
    ARTIFACT_TYPE, MEDIA_TYPE_CONFIG, MEDIA_TYPE_INDEX, MEDIA_TYPE_MANIFEST, MEDIA_TYPE_WASM_LAYER,
};

/// Everything [`build_and_publish`] needs, already extracted and owned by
/// the caller. Every field is validated again inside this crate; a caller
/// that already validated its own copy gets a cheap, redundant check, and a
/// caller that did not gets the real one.
pub struct OciPlan {
    /// The project's manifest name. Rendered as the OCI index's
    /// `org.opencontainers.image.ref.name` annotation and embedded in the
    /// config and manifest blobs.
    pub project_name: String,
    /// The project revision digest fact (`"sha256:" + 64 hex`) the rest of
    /// the compiler already computed and verified.
    pub project_revision: String,
    /// The workspace revision digest fact.
    pub workspace_revision: String,
    /// The project graph digest fact.
    pub project_graph_digest: String,
    /// The entry module's stable dotted identity.
    pub entry_module: String,
    /// The project's deterministic Wasm module bytes (e.g. Project v1's
    /// `app.wasm`), taken verbatim as the artifact's single content layer.
    pub wasm_bytes: Vec<u8>,
    /// The caller's own `sha256:`-prefixed digest of `wasm_bytes`. This
    /// crate recomputes the digest independently and refuses the plan if
    /// the two disagree, the same authenticate-before-trust discipline
    /// `semaprax-native-rust-owned-data-package` uses for its provider
    /// bytes.
    pub wasm_sha256: String,
}

/// The published artifact's identity, returned only after every blob has
/// been written and read back byte-for-byte.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OciBundle {
    output_directory: std::path::PathBuf,
    index_digest: String,
    manifest_digest: String,
    config_digest: String,
    layer_digest: String,
}

impl OciBundle {
    pub fn output_directory(&self) -> &std::path::Path {
        &self.output_directory
    }

    /// The `sha256:`-prefixed digest of `index.json`'s sole manifest entry.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// The `sha256:`-prefixed digest of the index's own referenced manifest
    /// blob (identical to [`Self::manifest_digest`]; kept as a separate
    /// accessor because a future multi-manifest index would not keep that
    /// equality).
    pub fn index_manifest_digest(&self) -> &str {
        &self.index_digest
    }

    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    pub fn layer_digest(&self) -> &str {
        &self.layer_digest
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OciErrorKind {
    /// A plan field failed admission: a hostile or malformed identity, or a
    /// Wasm-digest mismatch between the caller's claim and the actual bytes.
    Identity,
    /// The output path failed to be created, or a write/read-back failed.
    Publication,
}

/// An opaque packaging failure. Deliberately carries no more than a stable
/// kind and a short, non-sensitive message: this crate never echoes file
/// contents or environment values back into an error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OciError {
    kind: OciErrorKind,
    message: String,
}

impl OciError {
    pub fn kind(&self) -> OciErrorKind {
        self.kind
    }

    fn identity(message: impl Into<String>) -> Self {
        Self {
            kind: OciErrorKind::Identity,
            message: message.into(),
        }
    }

    fn credential_environment(names: String) -> Self {
        Self {
            kind: OciErrorKind::Identity,
            message: format!("refusing to run near a live registry credential: unset {names}"),
        }
    }

    fn publication_io(error: std::io::Error) -> Self {
        Self {
            kind: OciErrorKind::Publication,
            message: format!("OCI layout publication I/O failed: {error}"),
        }
    }

    fn publication_verification() -> Self {
        Self {
            kind: OciErrorKind::Publication,
            message: "OCI layout publication read-back disagreed with what was written".to_owned(),
        }
    }
}

impl std::fmt::Display for OciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OciError {}

fn validate_plan(plan: &OciPlan) -> Result<(), OciError> {
    if !validation::valid_identity_component(&plan.project_name) {
        return Err(OciError::identity(
            "project name is not an admitted identity",
        ));
    }
    if !validation::valid_stable_component(&plan.entry_module) {
        return Err(OciError::identity(
            "entry module is not an admitted stable identity",
        ));
    }
    for (name, value) in [
        ("project_revision", &plan.project_revision),
        ("workspace_revision", &plan.workspace_revision),
        ("project_graph_digest", &plan.project_graph_digest),
        ("wasm_sha256", &plan.wasm_sha256),
    ] {
        if !validation::valid_digest_fact(value) {
            return Err(OciError::identity(format!("{name} is not a digest fact")));
        }
    }
    if plan.wasm_bytes.is_empty() || plan.wasm_bytes.len() > MAX_WASM_BYTES {
        return Err(OciError::identity(
            "wasm module is empty or exceeds the packaging size ceiling",
        ));
    }
    if render::sha256_digest_fact(&plan.wasm_bytes) != plan.wasm_sha256 {
        return Err(OciError::identity(
            "claimed wasm sha256 disagrees with the actual bytes",
        ));
    }
    Ok(())
}

/// Render and publish one deterministic OCI Image Layout directory at
/// `output`, which must not already exist. Two calls with an identical
/// `plan` produce byte-identical files, including every digest.
pub fn build_and_publish(plan: OciPlan, output: &std::path::Path) -> Result<OciBundle, OciError> {
    validation::refuse_if_credential_environment_present()?;
    validate_plan(&plan)?;

    let config_bytes = render::render_config(&plan, &plan.wasm_sha256);
    let config_digest_hex = render::sha256_hex(&config_bytes);

    let layer_bytes = plan.wasm_bytes.clone();
    let layer_digest_hex = render::sha256_hex(&layer_bytes);

    let manifest_bytes = render::render_manifest(
        &plan,
        &format!("sha256:{config_digest_hex}"),
        config_bytes.len(),
        &format!("sha256:{layer_digest_hex}"),
        layer_bytes.len(),
    );
    let manifest_digest_hex = render::sha256_hex(&manifest_bytes);

    let index_bytes = render::render_index(
        &plan,
        &format!("sha256:{manifest_digest_hex}"),
        manifest_bytes.len(),
    );

    let layout = publish::RenderedLayout {
        oci_layout: render::oci_layout_bytes(),
        config_bytes,
        config_digest_hex: config_digest_hex.clone(),
        layer_bytes,
        layer_digest_hex: layer_digest_hex.clone(),
        manifest_bytes,
        manifest_digest_hex: manifest_digest_hex.clone(),
        index_bytes,
    };
    publish::publish(output, &layout)?;

    Ok(OciBundle {
        output_directory: output.to_path_buf(),
        index_digest: format!("sha256:{manifest_digest_hex}"),
        manifest_digest: format!("sha256:{manifest_digest_hex}"),
        config_digest: format!("sha256:{config_digest_hex}"),
        layer_digest: format!("sha256:{layer_digest_hex}"),
    })
}

#[cfg(test)]
mod tests;
