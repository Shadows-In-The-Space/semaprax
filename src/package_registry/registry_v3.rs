//! Additive producer-backed linked-root/leaf registry. No distribution effects.
use super::leaf_manifest_v1::{
    self as leaf, association, decode_wire, domain, encode, fail, Result,
};
use super::{PublicationStatus, PublishedEntry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DOCUMENT_SCHEMA: &str = "semaprax.package-registry-document.v3";
pub const SNAPSHOT_SCHEMA: &str = "semaprax.package-registry-snapshot.v3";
pub const MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fact {
    package: String,
    version: String,
    report: String,
    source: String,
    dependencies: Vec<(String, String)>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRow {
    package: String,
    version: String,
    kind: String,
    digest: String,
    bytes: String,
    build_facts: Vec<Fact>,
}
/// Only independent producer replay constructs this type.
#[derive(Clone, Debug)]
pub struct DistributionEntry {
    publication: PublishedEntry,
    manifest: ManifestRow,
}
impl DistributionEntry {
    pub fn publication(&self) -> &PublishedEntry {
        &self.publication
    }
    pub fn artifact_manifest_bytes(&self) -> &str {
        &self.manifest.bytes
    }
    pub fn artifact_manifest_digest(&self) -> &str {
        &self.manifest.digest
    }
}
/// Inspection only, no conversion to DistributionEntry or RegistrySnapshotV3.
#[derive(Clone, Debug)]
pub struct DecodedEntry {
    publication: PublishedEntry,
    manifest: ManifestRow,
}
impl DecodedEntry {
    pub fn publication(&self) -> &PublishedEntry {
        &self.publication
    }
    pub fn artifact_manifest_bytes(&self) -> &str {
        &self.manifest.bytes
    }
}

pub fn admit_leaf_build(
    publication: PublishedEntry,
    build: &crate::package_build::OfflinePackageBuild,
    evidence: &str,
    input: &crate::package_resolver::ResolutionInput,
    options: &crate::package_resolver::ResolutionOptions,
    build_options: &crate::package_build::OfflinePackageBuildOptions,
) -> Result<DistributionEntry> {
    let manifest =
        leaf::create_from_leaf_build(&publication, build, evidence, input, options, build_options)?;
    let subject = crate::package_lock_v3::verify_dependency_subject(&publication.subject_bytes)?;
    let mut publication = publication;
    publication.api_digest = manifest.api_abi_digest().into();
    let fact = Fact {
        package: publication.package.clone(),
        version: publication.version.clone(),
        report: subject.report,
        source: subject.canonical_source,
        dependencies: vec![],
    };
    Ok(DistributionEntry {
        manifest: ManifestRow {
            package: publication.package.clone(),
            version: publication.version.clone(),
            kind: "leaf-v1".into(),
            digest: manifest.digest().into(),
            bytes: manifest.bytes().into(),
            build_facts: vec![fact],
        },
        publication,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn admit_linked_build(
    publication: PublishedEntry,
    build: &crate::package_build_v2::LinkedOfflinePackageBuild,
    capsule: &str,
    sources: &[crate::package_source_capsule::PackageSource],
    evidence: &str,
    input: &crate::package_resolver::ResolutionInput,
    options: &crate::package_resolver::ResolutionOptions,
    capsule_options: &crate::package_source_capsule::SourceCapsuleOptions,
    build_options: &crate::package_build_v2::LinkedOfflinePackageBuildOptions,
) -> Result<DistributionEntry> {
    let admitted = super::registry_v2::admit_linked_build(
        publication,
        build,
        capsule,
        sources,
        evidence,
        input,
        options,
        capsule_options,
        build_options,
    )?;
    // Resolution and build have already replayed. Use the selected receipt,
    // never every unselected catalog entry, to recover retained source facts.
    let resolution = crate::package_resolver::verify(evidence, input, options)?;
    let mut work = 0;
    let mut facts = Vec::new();
    for coordinate in &resolution.packages {
        let mut matching = Vec::new();
        for bytes in &input.subjects {
            let subject =
                crate::package_lock_v2::authenticate_subject_for_package_source(bytes, &mut work)?;
            if subject.coordinate == *coordinate {
                matching.push(subject);
            }
        }
        if matching.len() != 1 {
            return Err(association("linked selected subject is not unique"));
        }
        let subject = matching.remove(0);
        let source = sources
            .iter()
            .find(|s| s.package == coordinate.package && s.report == subject.report)
            .ok_or_else(|| association("linked exact source/report missing"))?;
        facts.push(Fact {
            package: coordinate.package.clone(),
            version: coordinate.version.clone(),
            report: subject.report,
            source: source.source.clone(),
            dependencies: subject
                .dependencies
                .into_iter()
                .map(|d| (d.package, d.version))
                .collect(),
        });
    }
    facts.sort_by(|a, b| (&a.package, &a.version).cmp(&(&b.package, &b.version)));
    let publication = admitted.publication().clone();
    let entry = DistributionEntry {
        manifest: ManifestRow {
            package: publication.package.clone(),
            version: publication.version.clone(),
            kind: "linked-v2".into(),
            digest: admitted.artifact_manifest_digest().into(),
            bytes: admitted.artifact_manifest_bytes().into(),
            build_facts: facts,
        },
        publication,
    };
    check_declared_edges(&entry)?;
    Ok(entry)
}

fn own_fact(entry: &DistributionEntry) -> Result<&Fact> {
    entry
        .manifest
        .build_facts
        .iter()
        .find(|f| f.package == entry.publication.package && f.version == entry.publication.version)
        .ok_or_else(|| association("producer root fact missing"))
}
fn check_declared_edges(entry: &DistributionEntry) -> Result<()> {
    let subject =
        crate::package_lock_v3::verify_dependency_subject(&entry.publication.subject_bytes)?;
    let fact = own_fact(entry)?;
    let names = subject
        .dependencies
        .iter()
        .map(|d| d.package.as_str())
        .collect::<Vec<_>>();
    let actual = fact
        .dependencies
        .iter()
        .map(|d| d.0.as_str())
        .collect::<Vec<_>>();
    if names != actual || subject.report != fact.report {
        return Err(association(
            "Subject-v3 direct dependencies/report differ from verified build",
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    publications: String,
    manifests: Vec<ManifestRow>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    digest: String,
    bytes: usize,
    document: String,
}

/// Producer-backed snapshot. Byte-only decode returns a different type.
pub struct RegistrySnapshotV3 {
    entries: Vec<DistributionEntry>,
    envelope: String,
    digest: String,
}
impl RegistrySnapshotV3 {
    pub fn entries(&self) -> &[DistributionEntry] {
        &self.entries
    }
    pub fn envelope(&self) -> &str {
        &self.envelope
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
pub struct InspectedSnapshotV3 {
    entries: Vec<DecodedEntry>,
    envelope: String,
}
impl InspectedSnapshotV3 {
    pub fn entries(&self) -> &[DecodedEntry] {
        &self.entries
    }
    pub fn envelope(&self) -> &str {
        &self.envelope
    }
}

fn ordered(entries: &[DistributionEntry]) -> Result<Vec<DistributionEntry>> {
    if entries.is_empty() || entries.len() > super::MAX_ENTRIES {
        return Err(fail("registry-v3 inventory exceeds bound"));
    }
    let mut total = 0usize;
    for entry in entries {
        for len in std::iter::once(entry.publication.subject_bytes.len())
            .chain(std::iter::once(entry.manifest.bytes.len()))
            .chain(
                entry
                    .manifest
                    .build_facts
                    .iter()
                    .flat_map(|f| [f.source.len(), f.report.len()]),
            )
        {
            total = total
                .checked_add(len)
                .filter(|n| *n <= MAX_BYTES)
                .ok_or_else(|| fail("registry-v3 input bound exceeded"))?;
        }
    }
    let publications = entries
        .iter()
        .map(|e| e.publication.clone())
        .collect::<Vec<_>>();
    let registry = super::build_snapshot(&publications)?;
    let mut result = Vec::new();
    for (package, version) in registry.coordinates() {
        let entry = entries
            .iter()
            .find(|e| e.publication.package == package && e.publication.version == version)
            .expect("validated coordinate");
        validate_manifest(&entry.publication, &entry.manifest)?;
        check_declared_edges(entry)?;
        result.push(entry.clone());
    }
    Ok(result)
}
pub fn build_snapshot(entries: &[DistributionEntry]) -> Result<RegistrySnapshotV3> {
    let entries = ordered(entries)?;
    let document = encode(&Document {
        schema: DOCUMENT_SCHEMA.into(),
        publications: super::wire::render_registry_document(
            &entries
                .iter()
                .map(|e| e.publication.clone())
                .collect::<Vec<_>>(),
        ),
        manifests: entries.iter().map(|e| e.manifest.clone()).collect(),
    });
    if document.len() > MAX_BYTES {
        return Err(fail("registry-v3 document exceeds bound"));
    }
    let digest = domain(SNAPSHOT_SCHEMA, document.as_bytes());
    let envelope = encode(&Envelope {
        schema: SNAPSHOT_SCHEMA.into(),
        digest: digest.clone(),
        bytes: document.len(),
        document,
    });
    if envelope.len() > MAX_BYTES {
        return Err(fail("registry-v3 envelope exceeds bound"));
    }
    Ok(RegistrySnapshotV3 {
        entries,
        envelope,
        digest,
    })
}
pub fn verify_snapshot(bytes: &str, entries: &[DistributionEntry]) -> Result<RegistrySnapshotV3> {
    if bytes.len() > MAX_BYTES {
        return Err(fail("registry-v3 input exceeds bound"));
    }
    let snapshot = build_snapshot(entries)?;
    if bytes != snapshot.envelope {
        return Err(association("registry-v3 exact producer replay disagrees"));
    }
    Ok(snapshot)
}
fn validate_manifest(publication: &PublishedEntry, manifest: &ManifestRow) -> Result<()> {
    if manifest.package != publication.package || manifest.version != publication.version {
        return Err(association("manifest coordinate disagrees"));
    }
    match manifest.kind.as_str() {
        "leaf-v1" => {
            if !leaf::inspect_with_digest(&manifest.bytes, &manifest.digest)?.matches(publication) {
                return Err(association("leaf manifest publication differs"));
            }
        }
        "linked-v2" => {
            let inspected = super::artifact_manifest::verify(&manifest.bytes, &manifest.digest)?;
            let input = inspected.input();
            if input.package != publication.package
                || input.version != publication.version
                || input.content_digest != publication.content_digest
                || input.api_abi_digest != publication.api_digest
            {
                return Err(association("linked manifest publication differs"));
            }
        }
        _ => return Err(fail("unknown registry-v3 manifest profile")),
    }
    if manifest.build_facts.is_empty() || manifest.build_facts.len() > 4 {
        return Err(fail("build fact inventory exceeds bound"));
    }
    if manifest.kind == "leaf-v1"
        && (manifest.build_facts.len() != 1 || !manifest.build_facts[0].dependencies.is_empty())
    {
        return Err(fail("leaf build facts must be a dependency-free singleton"));
    }
    let mut previous = None;
    for fact in &manifest.build_facts {
        super::validate_identity(&fact.package)?;
        super::validate_version(&fact.version)?;
        let coordinate = (&fact.package, &fact.version);
        if previous.is_some_and(|p| p >= coordinate)
            || fact.source.len() > 1024 * 1024
            || fact.report.len() > crate::package_lock_v3::MAX_SUBJECT_BYTES
        {
            return Err(fail("build fact order or byte bound refused"));
        }
        previous = Some(coordinate);
        let mut last = None;
        for (package, version) in &fact.dependencies {
            super::validate_identity(package)?;
            super::validate_version(version)?;
            if last.is_some_and(|p| p >= package) {
                return Err(fail("build dependency order refused"));
            }
            last = Some(package);
        }
    }
    if !manifest
        .build_facts
        .iter()
        .any(|f| f.package == publication.package && f.version == publication.version)
    {
        return Err(association("manifest root fact missing"));
    }
    Ok(())
}
pub fn inspect_snapshot(bytes: &str) -> Result<InspectedSnapshotV3> {
    let envelope: Envelope = decode_wire(bytes, MAX_BYTES)?;
    if envelope.schema != SNAPSHOT_SCHEMA
        || envelope.document.len() != envelope.bytes
        || domain(SNAPSHOT_SCHEMA, envelope.document.as_bytes()) != envelope.digest
    {
        return Err(association("registry-v3 snapshot digest disagrees"));
    }
    let document: Document = decode_wire(&envelope.document, MAX_BYTES)?;
    if document.schema != DOCUMENT_SCHEMA {
        return Err(fail("registry-v3 document schema refused"));
    }
    let publications = super::wire::parse_registry_document(&document.publications)?;
    let registry = super::build_snapshot(&publications)?;
    let ordered_publications = registry
        .coordinates()
        .iter()
        .map(|(package, version)| {
            publications
                .iter()
                .find(|p| &p.package == package && &p.version == version)
                .expect("validated coordinate")
                .clone()
        })
        .collect::<Vec<_>>();
    if super::wire::render_registry_document(&ordered_publications) != document.publications {
        return Err(fail(
            "registry-v3 publication order or bytes are not canonical",
        ));
    }
    if publications.len() != document.manifests.len()
        || registry
            .coordinates()
            .iter()
            .zip(&document.manifests)
            .any(|((p, v), m)| p != &m.package || v != &m.version)
    {
        return Err(association(
            "registry-v3 manifest inventory or order disagrees",
        ));
    }
    let mut entries = Vec::new();
    for manifest in document.manifests {
        let publication = publications
            .iter()
            .find(|p| p.package == manifest.package && p.version == manifest.version)
            .ok_or_else(|| association("publication missing"))?
            .clone();
        validate_manifest(&publication, &manifest)?;
        entries.push(DecodedEntry {
            publication,
            manifest,
        });
    }
    Ok(InspectedSnapshotV3 {
        entries,
        envelope: bytes.into(),
    })
}

/// Pure evidence over a sealed snapshot, never a cache/fetch capability.
pub fn verify_lock_selection(
    snapshot: &RegistrySnapshotV3,
    lock: &str,
    subjects: &[String],
) -> Result<()> {
    let verified = crate::package_lock_v3::verify(lock, subjects, &Default::default())?;
    let mut selected = BTreeMap::new();
    for bytes in subjects {
        let entry = snapshot
            .entries
            .iter()
            .find(|e| {
                e.publication.subject_bytes == *bytes
                    && e.publication.status == PublicationStatus::Active
            })
            .ok_or_else(|| association("selected subject missing or yanked"))?;
        let subject = crate::package_lock_v3::verify_dependency_subject(bytes)?;
        let coordinate = (
            subject.coordinate.package.clone(),
            subject.coordinate.version.clone(),
        );
        if selected.insert(coordinate, (entry, subject)).is_some() {
            return Err(association("duplicate selection"));
        }
    }
    let locked_coordinates = verified
        .packages
        .iter()
        .map(|coordinate| (coordinate.package.clone(), coordinate.version.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    let selected_coordinates = selected
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if verified.packages.len() != selected.len() || locked_coordinates != selected_coordinates {
        return Err(association("lock selection inventory disagrees"));
    }
    for (entry, subject) in selected.values() {
        let fact = own_fact(entry)?;
        let mut edges = Vec::new();
        for dependency in &subject.dependencies {
            let coordinate = verified
                .packages
                .iter()
                .find(|c| c.package == dependency.package)
                .ok_or_else(|| association("locked dependency missing"))?;
            edges.push((coordinate.package.clone(), coordinate.version.clone()));
        }
        if edges != fact.dependencies {
            return Err(association(
                "Lock-v3 edges differ from independently built graph",
            ));
        }
        for fact in &entry.manifest.build_facts {
            let (dependency, _) = selected
                .get(&(fact.package.clone(), fact.version.clone()))
                .ok_or_else(|| association("built closure is absent from lock"))?;
            if own_fact(dependency)? != fact {
                return Err(association(
                    "selected dependency source/report/build graph differs",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
