//! Versioned dependency-free Build-v1 admission. Decoding is inspection only.
use crate::diagnostic::Diagnostic;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const SCHEMA: &str = "semaprax.package-leaf-artifact-manifest.v1";
pub const PROFILE: &str = "effect-free-core-wasm-scalar.v1";
pub const MAX_BYTES: usize = 256 * 1024;
pub(super) type Result<T> = std::result::Result<T, Diagnostic>;
pub(super) fn fail(message: &str) -> Diagnostic {
    Diagnostic::io("SPX-PKR630", message)
}
pub(super) fn association(message: &str) -> Diagnostic {
    Diagnostic::io("SPX-PKR631", message)
}
pub(super) fn raw(bytes: &[u8]) -> String {
    crate::audit_capsule::sha256_digest(bytes)
}
pub(super) fn domain(schema: &str, bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(schema.as_bytes());
    hash.update([0]);
    hash.update(bytes);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}
pub(super) fn encode<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("wire serializes")
}
pub(super) fn decode_wire<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &str,
    limit: usize,
) -> Result<T> {
    crate::package_build::wire::validate_compact_json_keys(bytes, limit, "registry distribution")
        .map_err(|_| fail("noncanonical or oversized distribution wire"))?;
    let value: T = serde_json::from_str(bytes).map_err(|_| fail("invalid distribution shape"))?;
    if encode(&value) != bytes {
        return Err(fail("noncanonical distribution encoding"));
    }
    Ok(value)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub role: String,
    pub path: String,
    pub bytes: usize,
    pub sha256: String,
    pub profile: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    package: String,
    version: String,
    content_digest: String,
    api_abi_digest: String,
    source_revision: String,
    report_digest: String,
    subject_v2_sha256: String,
    resolution_sha256: String,
    target_profile: String,
    features: Vec<String>,
    effects: Vec<String>,
    capabilities: Vec<String>,
    artifacts: Vec<Artifact>,
}

/// Independently reproduced compiler output; no constructor from wire bytes.
#[derive(Clone, Debug)]
pub struct AdmittedLeafManifest {
    inspected: InspectedLeafManifest,
}
impl AdmittedLeafManifest {
    pub fn bytes(&self) -> &str {
        self.inspected.bytes()
    }
    pub fn digest(&self) -> &str {
        self.inspected.digest()
    }
    pub fn api_abi_digest(&self) -> &str {
        &self.inspected.document.api_abi_digest
    }
}
/// Canonical byte inspection, never proof of compiler replay or publisher trust.
#[derive(Clone, Debug)]
pub struct InspectedLeafManifest {
    document: Document,
    bytes: String,
    digest: String,
}
impl InspectedLeafManifest {
    pub fn bytes(&self) -> &str {
        &self.bytes
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn artifacts(&self) -> &[Artifact] {
        &self.document.artifacts
    }
    pub(super) fn matches(&self, publication: &super::PublishedEntry) -> bool {
        self.document.package == publication.package
            && self.document.version == publication.version
            && self.document.content_digest == publication.content_digest
            && self.document.api_abi_digest == publication.api_digest
    }
}

pub fn create_from_leaf_build(
    publication: &super::PublishedEntry,
    build: &crate::package_build::OfflinePackageBuild,
    resolution_evidence: &str,
    resolution_input: &crate::package_resolver::ResolutionInput,
    resolution_options: &crate::package_resolver::ResolutionOptions,
    build_options: &crate::package_build::OfflinePackageBuildOptions,
) -> Result<AdmittedLeafManifest> {
    let receipt = crate::package_build::verify(
        build,
        resolution_evidence,
        resolution_input,
        resolution_options,
        build_options,
    )?;
    let subject = crate::package_lock_v3::verify_dependency_subject(&publication.subject_bytes)?;
    if subject.coordinate.package != publication.package
        || subject.coordinate.version != publication.version
        || !subject.dependencies.is_empty()
        || !subject.capabilities.is_empty()
        || receipt.root_package != publication.package
        || receipt.packages.len() != 1
        || receipt.packages[0].package != publication.package
        || receipt.packages[0].version != publication.version
    {
        return Err(association(
            "leaf coordinate or dependency-free association disagrees",
        ));
    }
    let expected_v2 =
        crate::package_lock_v2::create_subject(&receipt.packages[0], &subject.report, &[], &[])
            .map_err(|_| association("leaf Subject-v2 derivation failed"))?;
    // Catalogs may contain unselected entries. Exactly one selected coordinate
    // must have precisely the Report-v2 and canonical source replayed by v3.
    let mut work = 0;
    let mut selected = 0;
    for bytes in &resolution_input.subjects {
        let item = crate::package_lock_v2::authenticate_subject_for_resolution(bytes, &mut work)?;
        if item.coordinate == receipt.packages[0] {
            if *bytes != expected_v2 {
                return Err(association(
                    "leaf report/source or Subject-v2 bytes disagree",
                ));
            }
            selected += 1;
        }
    }
    if selected != 1 {
        return Err(association("leaf selected source is not unique"));
    }
    let manifest: serde_json::Value = serde_json::from_str(&build.manifest_json)
        .map_err(|_| association("verified build manifest missing"))?;
    let exports = manifest["exports"]
        .as_array()
        .ok_or_else(|| association("verified exports missing"))?;
    let api = domain(
        "semaprax.package-artifact-api-abi.v1",
        encode(exports).as_bytes(),
    );
    if !publication.api_digest.is_empty() && publication.api_digest != api {
        return Err(association(
            "supplied leaf API digest differs from verified exports",
        ));
    }
    let mut publication = publication.clone();
    publication.api_digest = api.clone();
    super::build_snapshot(std::slice::from_ref(&publication))?;
    let files: [(&str, &str, &[u8]); 3] = [
        ("core-wasm-module", "module.wasm", &build.module_wasm),
        (
            "build-evidence",
            "semaprax.package-build.evidence.json",
            build.evidence_json.as_bytes(),
        ),
        (
            "build-manifest",
            "semaprax.package-build.json",
            build.manifest_json.as_bytes(),
        ),
    ];
    let document = Document {
        schema: SCHEMA.into(),
        package: publication.package,
        version: publication.version,
        content_digest: publication.content_digest,
        api_abi_digest: api,
        source_revision: subject.source_revision,
        report_digest: subject.report_digest,
        subject_v2_sha256: raw(expected_v2.as_bytes()),
        resolution_sha256: raw(resolution_evidence.as_bytes()),
        target_profile: PROFILE.into(),
        features: vec!["scalar-exports".into()],
        effects: vec![],
        capabilities: vec![],
        artifacts: files
            .into_iter()
            .map(|(role, path, bytes)| Artifact {
                role: role.into(),
                path: path.into(),
                bytes: bytes.len(),
                sha256: raw(bytes),
                profile: PROFILE.into(),
            })
            .collect(),
    };
    let inspected = inspect(&encode(&document))?;
    if inspected
        .artifacts()
        .iter()
        .map(|row| row.bytes)
        .sum::<usize>()
        != receipt.artifact_bytes
    {
        return Err(association("leaf artifact accounting disagrees"));
    }
    Ok(AdmittedLeafManifest { inspected })
}

pub fn inspect(bytes: &str) -> Result<InspectedLeafManifest> {
    let document: Document = decode_wire(bytes, MAX_BYTES)?;
    super::validate_identity(&document.package)?;
    super::validate_version(&document.version)?;
    if document.schema != SCHEMA
        || document.target_profile != PROFILE
        || document.features != ["scalar-exports"]
        || !document.effects.is_empty()
        || !document.capabilities.is_empty()
        || document.artifacts.len() != 3
    {
        return Err(fail("leaf profile or inventory refused"));
    }
    for digest in [
        &document.content_digest,
        &document.api_abi_digest,
        &document.source_revision,
        &document.report_digest,
        &document.subject_v2_sha256,
        &document.resolution_sha256,
    ] {
        super::validate_digest_shape(digest, "leaf digest")?;
    }
    let mut total = 0usize;
    for (row, (role, path)) in document.artifacts.iter().zip([
        ("core-wasm-module", "module.wasm"),
        ("build-evidence", "semaprax.package-build.evidence.json"),
        ("build-manifest", "semaprax.package-build.json"),
    ]) {
        if row.role != role || row.path != path || row.profile != PROFILE || row.bytes == 0 {
            return Err(fail("leaf artifact inventory refused"));
        }
        super::validate_digest_shape(&row.sha256, "leaf artifact")?;
        total = total
            .checked_add(row.bytes)
            .filter(|n| *n <= crate::package_build::MAX_ARTIFACT_BYTES)
            .ok_or_else(|| fail("leaf artifacts exceed bound"))?;
    }
    Ok(InspectedLeafManifest {
        document,
        bytes: bytes.into(),
        digest: domain(SCHEMA, bytes.as_bytes()),
    })
}
pub fn inspect_with_digest(bytes: &str, expected: &str) -> Result<InspectedLeafManifest> {
    let inspected = inspect(bytes)?;
    if inspected.digest != expected {
        return Err(association("leaf manifest digest disagrees"));
    }
    Ok(inspected)
}
