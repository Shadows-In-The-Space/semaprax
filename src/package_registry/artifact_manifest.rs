//! Closed package-artifact manifest for the one registry profile that has an
//! independently replayable compiler producer today.
//!
//! The manifest is evidence only.  Decoding it does not open an artifact,
//! execute Wasm, fetch a package, publish bytes, or grant any authority.

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::bounded_output::{self, BudgetedJoin as _};
use crate::diagnostic::{quote_json, Diagnostic};

pub const SCHEMA: &str = "semaprax.package-artifact-manifest.v1";
pub const TARGET_PROFILE: &str = "linked-effect-free-core-wasm-scalar.v2";
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_INVENTORY_ITEMS: usize = 32;
pub const MAX_ARTIFACTS: usize = 3;
const DIGEST_DOMAIN: &[u8] = b"semaprax.package-artifact-manifest.v1\0";
const API_ABI_DOMAIN: &[u8] = b"semaprax.package-artifact-api-abi.v1\0";

pub const FEATURES: [&str; 2] = ["linked-packages", "scalar-exports"];
pub const NONCLAIMS: [&str; 7] = [
    "evidence_only_not_artifact_or_publication_authority",
    "no_filesystem_network_cache_process_or_registry_access",
    "no_signature_publisher_identity_or_transparency_claim",
    "no_native_component_model_wasi_or_dynamic_linking",
    "no_target_execution_or_cross_platform_conformance",
    "no_effects_or_capabilities",
    "only_linked_effect_free_core_wasm_scalar_v2",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRow {
    pub role: String,
    pub path: String,
    pub bytes: usize,
    pub sha256: String,
    pub profile: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageArtifactManifestInput {
    pub package: String,
    pub version: String,
    pub capsule_digest: String,
    pub content_digest: String,
    pub api_abi_digest: String,
    pub target_profile: String,
    pub features: Vec<String>,
    pub effects: Vec<String>,
    pub capabilities: Vec<String>,
    pub artifacts: Vec<ArtifactRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageArtifactManifest {
    input: PackageArtifactManifestInput,
    bytes: String,
    digest: String,
}

impl PackageArtifactManifest {
    #[must_use]
    pub fn input(&self) -> &PackageArtifactManifestInput {
        &self.input
    }

    #[must_use]
    pub fn bytes(&self) -> &str {
        &self.bytes
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub fn derived_api_abi_digest(&self) -> &str {
        &self.input.api_abi_digest
    }
}

fn create(input: PackageArtifactManifestInput) -> Result<PackageArtifactManifest, Diagnostic> {
    validate_input(&input)?;
    let (bytes, overflowed) = bounded_output::with_limit(MAX_MANIFEST_BYTES, || render(&input));
    if overflowed || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(limit("package artifact manifest exceeds its byte bound"));
    }
    let digest = digest(bytes.as_bytes());
    Ok(PackageArtifactManifest {
        input,
        bytes,
        digest,
    })
}

#[cfg(test)]
pub(crate) fn create_unverified_for_test(
    input: PackageArtifactManifestInput,
) -> Result<PackageArtifactManifest, Diagnostic> {
    create(input)
}

#[allow(clippy::too_many_arguments)]
pub fn create_from_linked_build(
    publication: &super::PublishedEntry,
    build: &crate::package_build_v2::LinkedOfflinePackageBuild,
    capsule: &str,
    sources: &[crate::package_source_capsule::PackageSource],
    resolution_evidence: &str,
    resolution_input: &crate::package_resolver::ResolutionInput,
    resolution_options: &crate::package_resolver::ResolutionOptions,
    capsule_options: &crate::package_source_capsule::SourceCapsuleOptions,
    build_options: &crate::package_build_v2::LinkedOfflinePackageBuildOptions,
) -> Result<PackageArtifactManifest, Diagnostic> {
    let verified = crate::package_build_v2::verify(
        build,
        capsule,
        sources,
        resolution_evidence,
        resolution_input,
        resolution_options,
        capsule_options,
        build_options,
    )?;
    let root = verified
        .packages
        .iter()
        .find(|coordinate| coordinate.package.as_str() == verified.root_package.as_str())
        .ok_or_else(|| association("verified linked build has no root coordinate"))?;
    if root.package.as_str() != publication.package.as_str()
        || root.version.as_str() != publication.version.as_str()
    {
        return Err(association(
            "verified linked build root does not equal the registry publication coordinate",
        ));
    }
    let subject = crate::package_lock_v3::verify_dependency_subject(&publication.subject_bytes)?;
    if subject.coordinate.package != publication.package
        || subject.coordinate.version != publication.version
        || sources
            .iter()
            .filter(|source| {
                source.package == publication.package && source.report == subject.report
            })
            .count()
            != 1
    {
        return Err(association(
            "verified linked build sources do not contain exactly the published Subject-v3 source",
        ));
    }
    let manifest: Value = serde_json::from_str(&build.manifest_json)
        .map_err(|_| association("verified linked build manifest cannot be decoded"))?;
    let capsule_digest = string(&manifest["inputs"]["capsule_digest"], "capsule digest")?;
    if capsule_digest != verified.capsule_digest {
        return Err(association(
            "verified linked build capsule digest is internally inconsistent",
        ));
    }
    let api_abi_digest = api_abi_digest(&manifest["exports"])?;
    let artifact_total = checked_artifact_total(
        build.module_wasm.len(),
        build.evidence_json.len(),
        build.manifest_json.len(),
    )?;
    if artifact_total != verified.artifact_bytes {
        return Err(association(
            "verified linked build artifact accounting is inconsistent",
        ));
    }
    let mut validated_publication = publication.clone();
    validated_publication.api_digest = api_abi_digest.clone();
    super::build_snapshot(std::slice::from_ref(&validated_publication))?;
    create(PackageArtifactManifestInput {
        package: publication.package.clone(),
        version: publication.version.clone(),
        capsule_digest,
        content_digest: publication.content_digest.clone(),
        api_abi_digest,
        target_profile: TARGET_PROFILE.to_owned(),
        features: FEATURES.iter().map(|value| (*value).to_owned()).collect(),
        effects: Vec::new(),
        capabilities: Vec::new(),
        artifacts: vec![
            artifact("core-wasm-module", "module.wasm", &build.module_wasm),
            artifact(
                "build-evidence",
                "semaprax.package-build.evidence.json",
                build.evidence_json.as_bytes(),
            ),
            artifact(
                "build-manifest",
                "semaprax.package-build.json",
                build.manifest_json.as_bytes(),
            ),
        ],
    })
}

pub fn decode(bytes: &str) -> Result<PackageArtifactManifest, Diagnostic> {
    let keys = crate::package_build::wire::validate_compact_json_keys(
        bytes,
        MAX_MANIFEST_BYTES,
        "package artifact manifest",
    )
    .map_err(|_| malformed("package artifact manifest is not bounded canonical JSON"))?;
    let value: Value = serde_json::from_str(bytes)
        .map_err(|_| malformed("package artifact manifest is not JSON"))?;
    let mut order = ObjectOrder::new(&keys);
    object(
        &value,
        &mut order,
        &[
            "schema",
            "package",
            "version",
            "capsule_digest",
            "content_digest",
            "api_abi_digest",
            "target_profile",
            "features",
            "effects",
            "capabilities",
            "artifacts",
            "nonclaims",
        ],
    )?;
    exact_string(&value["schema"], SCHEMA, "schema")?;
    let artifacts = array(&value["artifacts"], "artifacts")?
        .iter()
        .map(|row| parse_artifact(row, &mut order))
        .collect::<Result<Vec<_>, _>>()?;
    let input = PackageArtifactManifestInput {
        package: string(&value["package"], "package")?,
        version: string(&value["version"], "version")?,
        capsule_digest: string(&value["capsule_digest"], "capsule_digest")?,
        content_digest: string(&value["content_digest"], "content_digest")?,
        api_abi_digest: string(&value["api_abi_digest"], "api_abi_digest")?,
        target_profile: string(&value["target_profile"], "target_profile")?,
        features: string_array(&value["features"], "features")?,
        effects: string_array(&value["effects"], "effects")?,
        capabilities: string_array(&value["capabilities"], "capabilities")?,
        artifacts,
    };
    let nonclaims = string_array(&value["nonclaims"], "nonclaims")?;
    if nonclaims
        != NONCLAIMS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    {
        return Err(profile("package artifact manifest nonclaims are not exact"));
    }
    order.finish()?;
    let rebuilt = create(input)?;
    if rebuilt.bytes != bytes {
        return Err(malformed(
            "package artifact manifest is not in canonical byte form",
        ));
    }
    Ok(rebuilt)
}

pub fn verify(bytes: &str, expected_digest: &str) -> Result<PackageArtifactManifest, Diagnostic> {
    super::validate_digest_shape(expected_digest, "artifact_manifest_digest")?;
    let decoded = decode(bytes)?;
    if decoded.digest != expected_digest {
        return Err(association(
            "package artifact manifest digest does not bind the submitted canonical bytes",
        ));
    }
    Ok(decoded)
}

fn validate_input(input: &PackageArtifactManifestInput) -> Result<(), Diagnostic> {
    super::validate_identity(&input.package)?;
    super::validate_version(&input.version)?;
    super::validate_digest_shape(&input.capsule_digest, "capsule_digest")?;
    super::validate_digest_shape(&input.content_digest, "content_digest")?;
    super::validate_digest_shape(&input.api_abi_digest, "api_abi_digest")?;
    if input.target_profile != TARGET_PROFILE {
        return Err(profile(
            "package artifact manifest admits only the linked scalar Core-Wasm build-v2 profile",
        ));
    }
    if input.features
        != FEATURES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    {
        return Err(profile(
            "package artifact manifest feature inventory is not exact and canonical",
        ));
    }
    if !input.effects.is_empty() || !input.capabilities.is_empty() {
        return Err(profile(
            "package artifact manifest profile admits no effects or capabilities",
        ));
    }
    if input.features.len() > MAX_INVENTORY_ITEMS
        || input.effects.len() > MAX_INVENTORY_ITEMS
        || input.capabilities.len() > MAX_INVENTORY_ITEMS
    {
        return Err(limit(
            "package artifact manifest inventory exceeds its bound",
        ));
    }
    validate_artifacts(&input.artifacts)
}

fn validate_artifacts(rows: &[ArtifactRow]) -> Result<(), Diagnostic> {
    const EXPECTED: [(&str, &str); 3] = [
        ("core-wasm-module", "module.wasm"),
        ("build-evidence", "semaprax.package-build.evidence.json"),
        ("build-manifest", "semaprax.package-build.json"),
    ];
    if rows.len() != MAX_ARTIFACTS {
        return Err(profile(
            "package artifact manifest must contain the exact three-file build-v2 inventory",
        ));
    }
    let mut cumulative = 0usize;
    for (row, (role, path)) in rows.iter().zip(EXPECTED) {
        if row.role != role || row.path != path || row.profile != TARGET_PROFILE {
            return Err(profile(
                "package artifact row role, path, order, or profile is not exact",
            ));
        }
        if row.bytes == 0 || row.bytes > crate::package_build_v2::MAX_ARTIFACT_BYTES {
            return Err(limit("package artifact row byte count is outside bounds"));
        }
        cumulative = cumulative
            .checked_add(row.bytes)
            .filter(|value| *value <= crate::package_build_v2::MAX_ARTIFACT_BYTES)
            .ok_or_else(|| limit("package artifact cumulative byte count exceeds Build-v2"))?;
        super::validate_digest_shape(&row.sha256, "artifact sha256")?;
    }
    Ok(())
}

fn render(input: &PackageArtifactManifestInput) -> String {
    let strings = |values: &[String]| {
        values
            .iter()
            .map(|value| quote_json(value))
            .collect::<Vec<_>>()
            .budgeted_join(",")
    };
    let artifacts = input
        .artifacts
        .iter()
        .map(|row| {
            bounded_output::budgeted_format(format_args!(
                "{{\"role\":{},\"path\":{},\"bytes\":{},\"sha256\":{},\"profile\":{}}}",
                quote_json(&row.role),
                quote_json(&row.path),
                row.bytes,
                quote_json(&row.sha256),
                quote_json(&row.profile)
            ))
        })
        .collect::<Vec<_>>()
        .budgeted_join(",");
    bounded_output::budgeted_format(format_args!(
        "{{\"schema\":{},\"package\":{},\"version\":{},\"capsule_digest\":{},\"content_digest\":{},\"api_abi_digest\":{},\"target_profile\":{},\"features\":[{}],\"effects\":[{}],\"capabilities\":[{}],\"artifacts\":[{}],\"nonclaims\":[{}]}}",
        quote_json(SCHEMA),
        quote_json(&input.package),
        quote_json(&input.version),
        quote_json(&input.capsule_digest),
        quote_json(&input.content_digest),
        quote_json(&input.api_abi_digest),
        quote_json(&input.target_profile),
        strings(&input.features),
        strings(&input.effects),
        strings(&input.capabilities),
        artifacts,
        NONCLAIMS.iter().map(|value| quote_json(value)).collect::<Vec<_>>().budgeted_join(",")
    ))
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(bytes);
    format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    )
}

fn raw_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    )
}

fn api_abi_digest(exports: &Value) -> Result<String, Diagnostic> {
    let exports = exports
        .as_array()
        .ok_or_else(|| association("verified linked build exports are not an array"))?;
    let canonical = serde_json::to_vec(exports)
        .map_err(|_| association("verified linked build exports cannot be canonicalized"))?;
    let mut hasher = Sha256::new();
    hasher.update(API_ABI_DOMAIN);
    hasher.update(canonical);
    Ok(format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    ))
}

fn artifact(role: &str, path: &str, bytes: &[u8]) -> ArtifactRow {
    ArtifactRow {
        role: role.to_owned(),
        path: path.to_owned(),
        bytes: bytes.len(),
        sha256: raw_digest(bytes),
        profile: TARGET_PROFILE.to_owned(),
    }
}

fn checked_artifact_total(
    module_bytes: usize,
    evidence_bytes: usize,
    manifest_bytes: usize,
) -> Result<usize, Diagnostic> {
    module_bytes
        .checked_add(evidence_bytes)
        .and_then(|value| value.checked_add(manifest_bytes))
        .filter(|value| *value <= crate::package_build_v2::MAX_ARTIFACT_BYTES)
        .ok_or_else(|| limit("linked build cumulative artifact bytes exceed the global bound"))
}

fn parse_artifact(value: &Value, order: &mut ObjectOrder<'_>) -> Result<ArtifactRow, Diagnostic> {
    object(
        value,
        order,
        &["role", "path", "bytes", "sha256", "profile"],
    )?;
    let bytes = value["bytes"]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| malformed("artifact bytes is not a bounded unsigned integer"))?;
    Ok(ArtifactRow {
        role: string(&value["role"], "artifact role")?,
        path: string(&value["path"], "artifact path")?,
        bytes,
        sha256: string(&value["sha256"], "artifact sha256")?,
        profile: string(&value["profile"], "artifact profile")?,
    })
}

struct ObjectOrder<'a> {
    keys: &'a [Vec<String>],
    next: usize,
}

impl<'a> ObjectOrder<'a> {
    fn new(keys: &'a [Vec<String>]) -> Self {
        Self { keys, next: 0 }
    }

    fn finish(self) -> Result<(), Diagnostic> {
        if self.next == self.keys.len() {
            Ok(())
        } else {
            Err(malformed(
                "package artifact manifest object inventory is not exact",
            ))
        }
    }
}

fn object(value: &Value, order: &mut ObjectOrder<'_>, expected: &[&str]) -> Result<(), Diagnostic> {
    let actual = order.keys.get(order.next);
    order.next += 1;
    let expected = expected
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<Vec<_>>();
    if !value.is_object() || actual != Some(&expected) {
        return Err(malformed(
            "package artifact manifest object shape or field order is not exact",
        ));
    }
    Ok(())
}

fn array<'a>(value: &'a Value, label: &str) -> Result<&'a [Value], Diagnostic> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| malformed(format!("package artifact manifest {label} is not an array")))
}

fn string(value: &Value, label: &str) -> Result<String, Diagnostic> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| malformed(format!("package artifact manifest {label} is not a string")))
}

fn exact_string(value: &Value, expected: &str, label: &str) -> Result<(), Diagnostic> {
    if value.as_str() == Some(expected) {
        Ok(())
    } else {
        Err(malformed(format!(
            "package artifact manifest {label} is not exact"
        )))
    }
}

fn string_array(value: &Value, label: &str) -> Result<Vec<String>, Diagnostic> {
    let values = array(value, label)?;
    if values.len() > MAX_INVENTORY_ITEMS {
        return Err(limit(format!(
            "package artifact manifest {label} exceeds its item bound"
        )));
    }
    values.iter().map(|value| string(value, label)).collect()
}

fn malformed(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io("SPX-PKR614", message.into())
}

fn association(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io("SPX-PKR615", message.into())
}

fn profile(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io("SPX-PKR616", message.into())
}

fn limit(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io("SPX-PKR617", message.into())
}

#[cfg(test)]
mod tests;
