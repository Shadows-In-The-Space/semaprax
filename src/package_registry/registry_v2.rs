//! Registry document and snapshot v2.
//!
//! V2 leaves every v1 type, byte renderer, decoder, and digest domain intact.
//! Its sole addition is an exact binding from a published Subject-v3 entry to
//! one canonical [`super::artifact_manifest`] envelope.  All APIs here are
//! pure in-memory construction or replay; decoded evidence grants no ambient
//! authority.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::bounded_output::{self, BudgetedJoin as _};
use crate::diagnostic::{quote_json, Diagnostic};
use crate::package_range::Version;

use super::{PublicationStatus, PublishedEntry, RegistrySignature};

pub const DOCUMENT_SCHEMA: &str = "semaprax.package-registry-document.v2";
pub const SNAPSHOT_SCHEMA: &str = "semaprax.package-registry-snapshot.v2";
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const SNAPSHOT_DOMAIN: &[u8] = b"semaprax.package-registry-snapshot.v2\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestBoundEntry {
    publication: PublishedEntry,
    artifact_manifest_digest: String,
    artifact_manifest_bytes: String,
}

impl ManifestBoundEntry {
    #[must_use]
    pub fn publication(&self) -> &PublishedEntry {
        &self.publication
    }

    #[must_use]
    pub fn artifact_manifest_digest(&self) -> &str {
        &self.artifact_manifest_digest
    }

    #[must_use]
    pub fn artifact_manifest_bytes(&self) -> &str {
        &self.artifact_manifest_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedManifestBoundEntry {
    publication: PublishedEntry,
    artifact_manifest_digest: String,
    artifact_manifest_bytes: String,
}

impl DecodedManifestBoundEntry {
    #[must_use]
    pub fn publication(&self) -> &PublishedEntry {
        &self.publication
    }

    #[must_use]
    pub fn artifact_manifest_digest(&self) -> &str {
        &self.artifact_manifest_digest
    }

    #[must_use]
    pub fn artifact_manifest_bytes(&self) -> &str {
        &self.artifact_manifest_bytes
    }
}

#[allow(clippy::too_many_arguments)]
pub fn admit_linked_build(
    publication: PublishedEntry,
    build: &crate::package_build_v2::LinkedOfflinePackageBuild,
    capsule: &str,
    sources: &[crate::package_source_capsule::PackageSource],
    resolution_evidence: &str,
    resolution_input: &crate::package_resolver::ResolutionInput,
    resolution_options: &crate::package_resolver::ResolutionOptions,
    capsule_options: &crate::package_source_capsule::SourceCapsuleOptions,
    build_options: &crate::package_build_v2::LinkedOfflinePackageBuildOptions,
) -> Result<ManifestBoundEntry, Diagnostic> {
    let manifest = super::artifact_manifest::create_from_linked_build(
        &publication,
        build,
        capsule,
        sources,
        resolution_evidence,
        resolution_input,
        resolution_options,
        capsule_options,
        build_options,
    )?;
    let mut publication = publication;
    publication.api_digest = manifest.derived_api_abi_digest().to_owned();
    Ok(ManifestBoundEntry {
        publication,
        artifact_manifest_digest: manifest.digest().to_owned(),
        artifact_manifest_bytes: manifest.bytes().to_owned(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrySnapshotV2 {
    entries: Vec<DecodedManifestBoundEntry>,
    document: String,
    envelope: String,
    digest: String,
}

impl RegistrySnapshotV2 {
    #[must_use]
    pub fn entries(&self) -> &[DecodedManifestBoundEntry] {
        &self.entries
    }

    #[must_use]
    pub fn document(&self) -> &str {
        &self.document
    }

    #[must_use]
    pub fn envelope(&self) -> &str {
        &self.envelope
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

pub fn build_snapshot(entries: &[ManifestBoundEntry]) -> Result<RegistrySnapshotV2, Diagnostic> {
    let entries = validate_and_order(entries)?
        .iter()
        .map(decoded_entry)
        .collect::<Vec<_>>();
    let (document, overflowed) =
        bounded_output::with_limit(MAX_DOCUMENT_BYTES, || render_document_ordered(&entries));
    if overflowed || document.len() > MAX_DOCUMENT_BYTES {
        return Err(limit("registry document v2 exceeds its byte bound"));
    }
    finish_snapshot(entries, document)
}

pub fn render_registry_document(entries: &[ManifestBoundEntry]) -> Result<String, Diagnostic> {
    build_snapshot(entries).map(|snapshot| snapshot.document)
}

pub fn parse_registry_document(bytes: &str) -> Result<Vec<DecodedManifestBoundEntry>, Diagnostic> {
    let keys = canonical_keys(bytes, MAX_DOCUMENT_BYTES, "registry document v2")?;
    let value: Value =
        serde_json::from_str(bytes).map_err(|_| malformed("registry document v2 is not JSON"))?;
    let mut order = ObjectOrder::new(&keys);
    object(&value, &mut order, &["schema", "entries"])?;
    exact_string(&value["schema"], DOCUMENT_SCHEMA, "document schema")?;
    let rows = array(&value["entries"], "entries")?;
    if rows.is_empty() || rows.len() > super::MAX_ENTRIES {
        return Err(limit("registry document v2 entry count is outside bounds"));
    }
    let entries = rows
        .iter()
        .map(|row| parse_entry(row, &mut order))
        .collect::<Result<Vec<_>, _>>()?;
    order.finish()?;
    let ordered = validate_decoded_and_order(&entries)?;
    let (rerendered, overflowed) =
        bounded_output::with_limit(MAX_DOCUMENT_BYTES, || render_document_ordered(&ordered));
    if overflowed || ordered != entries || rerendered != bytes {
        return Err(malformed(
            "registry document v2 entries or bytes are not canonical",
        ));
    }
    Ok(entries)
}

pub fn decode_snapshot(bytes: &str) -> Result<RegistrySnapshotV2, Diagnostic> {
    let keys = canonical_keys(bytes, MAX_SNAPSHOT_BYTES, "registry snapshot v2")?;
    let value: Value =
        serde_json::from_str(bytes).map_err(|_| malformed("registry snapshot v2 is not JSON"))?;
    let mut order = ObjectOrder::new(&keys);
    object(
        &value,
        &mut order,
        &["schema", "digest", "bytes", "document"],
    )?;
    exact_string(&value["schema"], SNAPSHOT_SCHEMA, "snapshot schema")?;
    let claimed_digest = string(&value["digest"], "snapshot digest")?;
    super::validate_digest_shape(&claimed_digest, "snapshot digest")?;
    let claimed_bytes = usize_value(&value["bytes"], "snapshot document bytes")?;
    let document = string(&value["document"], "snapshot document")?;
    order.finish()?;
    if claimed_bytes != document.len() {
        return Err(association(
            "registry snapshot v2 byte count does not bind its document",
        ));
    }
    let entries = parse_registry_document(&document)?;
    let rebuilt = finish_snapshot(entries, document)?;
    if rebuilt.digest != claimed_digest || rebuilt.envelope != bytes {
        return Err(association(
            "registry snapshot v2 digest or canonical envelope does not replay",
        ));
    }
    Ok(rebuilt)
}

pub fn verify_snapshot(
    evidence: &str,
    entries: &[ManifestBoundEntry],
) -> Result<RegistrySnapshotV2, Diagnostic> {
    let decoded = decode_snapshot(evidence)?;
    let rebuilt = build_snapshot(entries)?;
    if decoded.envelope != rebuilt.envelope {
        return Err(association(
            "registry snapshot v2 does not exactly replay the supplied entries",
        ));
    }
    Ok(decoded)
}

fn finish_snapshot(
    entries: Vec<DecodedManifestBoundEntry>,
    document: String,
) -> Result<RegistrySnapshotV2, Diagnostic> {
    let digest = snapshot_digest(document.as_bytes());
    let (envelope, overflowed) = bounded_output::with_limit(MAX_SNAPSHOT_BYTES, || {
        bounded_output::budgeted_format(format_args!(
            "{{\"schema\":{},\"digest\":{},\"bytes\":{},\"document\":{}}}",
            quote_json(SNAPSHOT_SCHEMA),
            quote_json(&digest),
            document.len(),
            quote_json(&document)
        ))
    });
    if overflowed || envelope.len() > MAX_SNAPSHOT_BYTES {
        return Err(limit("registry snapshot v2 exceeds its byte bound"));
    }
    Ok(RegistrySnapshotV2 {
        entries,
        document,
        envelope,
        digest,
    })
}

fn validate_and_order(
    entries: &[ManifestBoundEntry],
) -> Result<Vec<ManifestBoundEntry>, Diagnostic> {
    if entries.is_empty() || entries.len() > super::MAX_ENTRIES {
        return Err(limit("registry snapshot v2 entry count is outside bounds"));
    }
    let publications = entries
        .iter()
        .map(|entry| entry.publication.clone())
        .collect::<Vec<_>>();
    // Reuse, rather than fork, every v1 publication and Subject-v3 invariant.
    super::build_snapshot(&publications)?;
    let mut ordered = BTreeMap::<(String, Version), ManifestBoundEntry>::new();
    for entry in entries {
        let manifest = super::artifact_manifest::verify(
            &entry.artifact_manifest_bytes,
            &entry.artifact_manifest_digest,
        )?;
        let input = manifest.input();
        if input.package != entry.publication.package
            || input.version != entry.publication.version
            || input.content_digest != entry.publication.content_digest
            || input.api_abi_digest != entry.publication.api_digest
        {
            return Err(association(
                "registry entry and package artifact manifest association is not exact",
            ));
        }
        let version = super::validate_version(&entry.publication.version)?;
        ordered.insert((entry.publication.package.clone(), version), entry.clone());
    }
    Ok(ordered.into_values().collect())
}

fn validate_decoded_and_order(
    entries: &[DecodedManifestBoundEntry],
) -> Result<Vec<DecodedManifestBoundEntry>, Diagnostic> {
    if entries.is_empty() || entries.len() > super::MAX_ENTRIES {
        return Err(limit("registry document v2 entry count is outside bounds"));
    }
    let publications = entries
        .iter()
        .map(|entry| entry.publication.clone())
        .collect::<Vec<_>>();
    super::build_snapshot(&publications)?;
    let mut ordered = BTreeMap::<(String, Version), DecodedManifestBoundEntry>::new();
    for entry in entries {
        let manifest = super::artifact_manifest::verify(
            &entry.artifact_manifest_bytes,
            &entry.artifact_manifest_digest,
        )?;
        let input = manifest.input();
        if input.package != entry.publication.package
            || input.version != entry.publication.version
            || input.content_digest != entry.publication.content_digest
            || input.api_abi_digest != entry.publication.api_digest
        {
            return Err(association(
                "decoded registry entry and artifact manifest association is not exact",
            ));
        }
        let version = super::validate_version(&entry.publication.version)?;
        ordered.insert((entry.publication.package.clone(), version), entry.clone());
    }
    Ok(ordered.into_values().collect())
}

fn render_document_ordered(entries: &[DecodedManifestBoundEntry]) -> String {
    let rows = entries
        .iter()
        .map(render_entry)
        .collect::<Vec<_>>()
        .budgeted_join(",");
    bounded_output::budgeted_format(format_args!(
        "{{\"schema\":{},\"entries\":[{}]}}",
        quote_json(DOCUMENT_SCHEMA),
        rows
    ))
}

fn render_entry(entry: &DecodedManifestBoundEntry) -> String {
    let publication = &entry.publication;
    let (status, reason) = match &publication.status {
        PublicationStatus::Active => ("active", "null".to_owned()),
        PublicationStatus::Yanked { reason } => ("yanked", quote_json(reason)),
    };
    bounded_output::budgeted_format(format_args!(
        "{{\"package\":{},\"version\":{},\"content_digest\":{},\"api_digest\":{},\"license\":{},\"provenance_digest\":{},\"signature\":{{\"algorithm\":{},\"identity\":{},\"signature\":{}}},\"status\":{{\"state\":{},\"reason\":{}}},\"subject_bytes\":{},\"artifact_manifest_digest\":{},\"artifact_manifest_bytes\":{}}}",
        quote_json(&publication.package),
        quote_json(&publication.version),
        quote_json(&publication.content_digest),
        quote_json(&publication.api_digest),
        quote_json(&publication.license),
        publication.provenance_digest.as_ref().map_or_else(|| "null".to_owned(), |value| quote_json(value)),
        quote_json(&publication.signature.algorithm),
        quote_json(&publication.signature.identity),
        quote_json(&publication.signature.signature),
        quote_json(status),
        reason,
        quote_json(&publication.subject_bytes),
        quote_json(&entry.artifact_manifest_digest),
        quote_json(&entry.artifact_manifest_bytes)
    ))
}

fn parse_entry(
    value: &Value,
    order: &mut ObjectOrder<'_>,
) -> Result<DecodedManifestBoundEntry, Diagnostic> {
    object(
        value,
        order,
        &[
            "package",
            "version",
            "content_digest",
            "api_digest",
            "license",
            "provenance_digest",
            "signature",
            "status",
            "subject_bytes",
            "artifact_manifest_digest",
            "artifact_manifest_bytes",
        ],
    )?;
    object(
        &value["signature"],
        order,
        &["algorithm", "identity", "signature"],
    )?;
    object(&value["status"], order, &["state", "reason"])?;
    let state = string(&value["status"]["state"], "status state")?;
    let reason = &value["status"]["reason"];
    let status = match state.as_str() {
        "active" if reason.is_null() => PublicationStatus::Active,
        "yanked" => PublicationStatus::Yanked {
            reason: string(reason, "yank reason")?,
        },
        _ => return Err(malformed("registry document v2 status is not exact")),
    };
    let provenance_digest = if value["provenance_digest"].is_null() {
        None
    } else {
        Some(string(&value["provenance_digest"], "provenance digest")?)
    };
    Ok(DecodedManifestBoundEntry {
        publication: PublishedEntry {
            package: string(&value["package"], "package")?,
            version: string(&value["version"], "version")?,
            content_digest: string(&value["content_digest"], "content digest")?,
            api_digest: string(&value["api_digest"], "API digest")?,
            license: string(&value["license"], "license")?,
            provenance_digest,
            signature: RegistrySignature {
                algorithm: string(&value["signature"]["algorithm"], "signature algorithm")?,
                identity: string(&value["signature"]["identity"], "signature identity")?,
                signature: string(&value["signature"]["signature"], "signature bytes")?,
            },
            status,
            subject_bytes: string(&value["subject_bytes"], "subject bytes")?,
        },
        artifact_manifest_digest: string(
            &value["artifact_manifest_digest"],
            "artifact manifest digest",
        )?,
        artifact_manifest_bytes: string(
            &value["artifact_manifest_bytes"],
            "artifact manifest bytes",
        )?,
    })
}

fn decoded_entry(entry: &ManifestBoundEntry) -> DecodedManifestBoundEntry {
    DecodedManifestBoundEntry {
        publication: entry.publication.clone(),
        artifact_manifest_digest: entry.artifact_manifest_digest.clone(),
        artifact_manifest_bytes: entry.artifact_manifest_bytes.clone(),
    }
}

fn snapshot_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_DOMAIN);
    hasher.update(bytes);
    format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    )
}

fn canonical_keys(
    bytes: &str,
    maximum: usize,
    label: &str,
) -> Result<Vec<Vec<String>>, Diagnostic> {
    crate::package_build::wire::validate_compact_json_keys(bytes, maximum, label)
        .map_err(|_| malformed(format!("{label} is not bounded canonical JSON")))
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
            Err(malformed("registry v2 object inventory is not exact"))
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
            "registry v2 object shape or field order is not exact",
        ));
    }
    Ok(())
}

fn array<'a>(value: &'a Value, label: &str) -> Result<&'a [Value], Diagnostic> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| malformed(format!("registry v2 {label} is not an array")))
}

fn string(value: &Value, label: &str) -> Result<String, Diagnostic> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| malformed(format!("registry v2 {label} is not a string")))
}

fn exact_string(value: &Value, expected: &str, label: &str) -> Result<(), Diagnostic> {
    if value.as_str() == Some(expected) {
        Ok(())
    } else {
        Err(malformed(format!("registry v2 {label} is not exact")))
    }
}

fn usize_value(value: &Value, label: &str) -> Result<usize, Diagnostic> {
    value
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| malformed(format!("registry v2 {label} is not a bounded integer")))
}

fn malformed(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io("SPX-PKR618", message.into())
}

fn association(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io("SPX-PKR619", message.into())
}

fn limit(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io("SPX-PKR620", message.into())
}

#[cfg(test)]
mod tests;
