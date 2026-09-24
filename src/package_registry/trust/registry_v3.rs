//! Metadata-v2 signatures over producer-backed Registry-v3. Pure evidence only;
//! fixed trusted time/checkpoint/root are explicit caller inputs, never ambient.
use super::*;
use crate::package_registry::{artifact_manifest, leaf_manifest_v1, registry_v3 as registry};

pub const METADATA_SCHEMA_V2: &str = "semaprax.registry-trust-metadata.v2";
/// Wavect's local mirror policy: after a successful signed timestamp update,
/// an offline consumer may not keep accepting the old state for over seven
/// days. The first independently authorized install is exempt because it has
/// no prior timestamp observation to age.
pub const MAX_MIRROR_OFFLINE_SECONDS: u64 = 7 * 24 * 60 * 60;
const DOMAIN: &[u8] = b"semaprax.registry-trust-metadata.v2\0";
const CHECKPOINT_SCHEMA_V2: &str = "semaprax.registry-trust-checkpoint.v2";

/// Protocol floor for Registry-v3 / signed metadata-v2. Its private v1 stamps
/// preserve every high-water mark, but cannot be passed back to the v1 verifier.
#[derive(Clone)]
pub struct RegistryCheckpoint {
    previous: Checkpoint,
    publishers: BTreeMap<String, String>,
}
fn publisher_bindings(root: &InstalledRoot) -> BTreeMap<String, String> {
    root.roles
        .iter()
        .filter(|(_, role)| !role.namespace.is_empty())
        .map(|(name, role)| (name.clone(), role.namespace.clone()))
        .collect()
}
impl RegistryCheckpoint {
    /// Only for independently authorized first install, never corrupt-store fallback.
    pub fn initial(root: &InstalledRoot) -> Self {
        Self {
            previous: Checkpoint::initial(root),
            publishers: publisher_bindings(root),
        }
    }
    /// Explicit one-way protocol migration. The caller must durably commit this
    /// transition before treating it as authoritative; no high-water is reset.
    pub fn migrate_from_v1(checkpoint: &Checkpoint, root: &InstalledRoot) -> Result<Self> {
        if checkpoint.registry != root.registry
            || checkpoint.root_version != root.version
            || checkpoint.root_digest != root.digest
            || checkpoint
                .roles
                .keys()
                .any(|name| !root.roles.contains_key(name))
        {
            return Err(stale());
        }
        Ok(Self {
            previous: checkpoint.clone(),
            publishers: publisher_bindings(root),
        })
    }
    pub fn canonical_bytes(&self) -> String {
        let publishers = self
            .publishers
            .iter()
            .map(|(role, namespace)| json!({"role":role,"namespace":namespace}))
            .collect::<Vec<_>>();
        wire(
            &json!({"schema":CHECKPOINT_SCHEMA_V2,"checkpoint":self.previous.canonical_bytes(),"publishers":publishers}),
        )
    }
    pub fn from_trusted_store_bytes(bytes: &str) -> Result<Self> {
        let value = parse(bytes)?;
        fields(&value, &["schema", "checkpoint", "publishers"])?;
        if value["schema"] != CHECKPOINT_SCHEMA_V2 {
            return Err(shape());
        }
        let mut publishers = BTreeMap::new();
        for row in array(&value["publishers"], MAX_ROLES - 3)? {
            fields(row, &["role", "namespace"])?;
            let role = text(&row["role"])?;
            let namespace = text(&row["namespace"])?;
            label(role)?;
            label(namespace)?;
            if matches!(role, "root" | "timestamp" | "snapshot")
                || !namespace.ends_with('.')
                || publishers
                    .insert(role.to_owned(), namespace.to_owned())
                    .is_some()
            {
                return Err(shape());
            }
        }
        let checkpoint = Self {
            previous: Checkpoint::from_trusted_store_bytes(
                value["checkpoint"].as_str().ok_or_else(shape)?,
            )?,
            publishers,
        };
        if checkpoint.canonical_bytes() != bytes {
            return Err(shape());
        }
        Ok(checkpoint)
    }
}

pub struct UpdateInputs<'registry, 'metadata> {
    pub timestamp: &'metadata str,
    pub snapshot: &'metadata str,
    pub publishers: &'metadata [(&'metadata str, &'metadata str)],
    /// Only an independently admitted snapshot; inspection types cannot enter.
    pub registry: &'registry registry::RegistrySnapshotV3,
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
mod mirror;
#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
pub use mirror::{verify_mirror_update, MirrorMetadataPaths, MirrorPublisherPath};

/// Borrowed compiler-admitted registry plus a required checkpoint transition.
/// This does not persist the checkpoint or authorize cache/fetch/execution.
pub struct RegistryUpdateCandidate<'a> {
    registry: &'a registry::RegistrySnapshotV3,
    checkpoint: RegistryCheckpoint,
    prior_checkpoint_digest: String,
}
impl RegistryUpdateCandidate<'_> {
    pub fn checkpoint(&self) -> &RegistryCheckpoint {
        &self.checkpoint
    }
    pub fn prior_checkpoint_digest(&self) -> &str {
        &self.prior_checkpoint_digest
    }
    pub fn registry_snapshot_digest(&self) -> &str {
        self.registry.digest()
    }
    pub fn check_lock(&self, lock: &str, subjects: &[String]) -> Result<()> {
        registry::verify_lock_selection(self.registry, lock, subjects)
    }
    pub fn check_artifact(
        &self,
        package: &str,
        version: &str,
        path: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let entry = self
            .registry
            .entries()
            .iter()
            .find(|entry| {
                entry.publication().package == package && entry.publication().version == version
            })
            .ok_or_else(binding)?;
        if entry.publication().status != super::super::PublicationStatus::Active {
            return Err(error("SPX-PKR625", "yanked artifact is refused"));
        }
        let matched = match manifest_schema(entry)? {
            artifact_manifest::SCHEMA => artifact_manifest::verify(
                entry.artifact_manifest_bytes(),
                entry.artifact_manifest_digest(),
            )?
            .input()
            .artifacts
            .iter()
            .any(|row| row.path == path && row.bytes == bytes.len() && row.sha256 == hash(bytes)),
            leaf_manifest_v1::SCHEMA => leaf_manifest_v1::inspect_with_digest(
                entry.artifact_manifest_bytes(),
                entry.artifact_manifest_digest(),
            )?
            .artifacts()
            .iter()
            .any(|row| row.path == path && row.bytes == bytes.len() && row.sha256 == hash(bytes)),
            _ => false,
        };
        if !matched {
            return Err(binding());
        }
        Ok(())
    }
}

fn manifest_schema(entry: &registry::DistributionEntry) -> Result<&'static str> {
    // Entry is sealed producer output; parsing is only profile dispatch, never
    // an admission mechanism. Each branch still replays the manifest binding.
    let value: Value =
        serde_json::from_str(entry.artifact_manifest_bytes()).map_err(|_| binding())?;
    match value["schema"].as_str() {
        Some(artifact_manifest::SCHEMA) => Ok(artifact_manifest::SCHEMA),
        Some(leaf_manifest_v1::SCHEMA) => Ok(leaf_manifest_v1::SCHEMA),
        _ => Err(binding()),
    }
}

pub fn verify_update<'a>(
    root: &InstalledRoot,
    stored: &RegistryCheckpoint,
    now: u64,
    input: &UpdateInputs<'a, '_>,
) -> Result<RegistryUpdateCandidate<'a>> {
    let checkpoint = &stored.previous;
    if stored.publishers != publisher_bindings(root) {
        return Err(stale());
    }
    if root.registry != checkpoint.registry
        || root.expires <= now
        || now < checkpoint.observed_time
        || root.version < checkpoint.root_version
        || (root.version == checkpoint.root_version && root.digest != checkpoint.root_digest)
    {
        return Err(stale());
    }
    if Some(input.publishers.len()) != root.roles.len().checked_sub(3) {
        return Err(binding());
    }
    let authenticate = |role, bytes| {
        authenticate_profile(
            root,
            checkpoint,
            role,
            bytes,
            now,
            METADATA_SCHEMA_V2,
            DOMAIN,
        )
    };
    let timestamp = authenticate("timestamp", input.timestamp)?;
    fields(&timestamp.payload, &["snapshot"])?;
    let snapshot = authenticate("snapshot", input.snapshot)?;
    matches_metadata(&timestamp.payload["snapshot"], input.snapshot, &snapshot)?;
    fields(&snapshot.payload, &["registry", "publishers"])?;
    fields(&snapshot.payload["registry"], &["schema", "file"])?;
    if snapshot.payload["registry"]["schema"] != registry::SNAPSHOT_SCHEMA {
        return Err(binding());
    }
    matches_blob(
        &snapshot.payload["registry"]["file"],
        input.registry.envelope().as_bytes(),
        registry::MAX_BYTES,
    )?;
    let refs = array(&snapshot.payload["publishers"], MAX_ROLES)?;
    if refs.len() != input.publishers.len() {
        return Err(binding());
    }
    let mut names = BTreeSet::new();
    let mut targets = BTreeMap::new();
    let mut next = checkpoint.clone();
    for (name, bytes) in input.publishers {
        let role = root
            .roles
            .get(*name)
            .filter(|role| !role.namespace.is_empty())
            .ok_or_else(signature)?;
        if !names.insert(*name) {
            return Err(binding());
        }
        let metadata = authenticate(name, bytes)?;
        let matching = refs
            .iter()
            .filter(|row| row["role"] == *name)
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(binding());
        }
        fields(matching[0], &["role", "metadata"])?;
        matches_metadata(&matching[0]["metadata"], bytes, &metadata)?;
        fields(&metadata.payload, &["targets"])?;
        for target in array(&metadata.payload["targets"], super::super::MAX_ENTRIES)? {
            fields(target, &["package", "version", "manifest"])?;
            let package = text(&target["package"])?;
            let version = text(&target["version"])?;
            if !package.starts_with(&role.namespace) {
                return Err(signature());
            }
            if targets
                .insert(
                    (package.to_owned(), version.to_owned()),
                    target["manifest"].clone(),
                )
                .is_some()
                || targets.len() > super::super::MAX_ENTRIES
            {
                return Err(binding());
            }
        }
        next.roles.insert(
            (*name).into(),
            Stamp {
                version: metadata.version,
                digest: metadata.digest,
            },
        );
    }
    if targets.len() != input.registry.entries().len() {
        return Err(binding());
    }
    for entry in input.registry.entries() {
        let publication = entry.publication();
        let reference = targets
            .get(&(publication.package.clone(), publication.version.clone()))
            .ok_or_else(binding)?;
        fields(reference, &["schema", "digest", "file"])?;
        if reference["schema"] != manifest_schema(entry)?
            || reference["digest"] != entry.artifact_manifest_digest()
        {
            return Err(binding());
        }
        matches_blob(
            &reference["file"],
            entry.artifact_manifest_bytes().as_bytes(),
            artifact_manifest::MAX_MANIFEST_BYTES,
        )?;
    }
    // No inspect/decode path exists here: the borrowed snapshot carries sealed
    // independently replayed source/build/API/dependency facts.
    next.root_version = root.version;
    next.root_digest = root.digest.clone();
    next.observed_time = now;
    next.roles.insert(
        "timestamp".into(),
        Stamp {
            version: timestamp.version,
            digest: timestamp.digest,
        },
    );
    next.roles.insert(
        "snapshot".into(),
        Stamp {
            version: snapshot.version,
            digest: snapshot.digest,
        },
    );
    if next.roles.len() > MAX_ROLES {
        return Err(shape());
    }
    Ok(RegistryUpdateCandidate {
        registry: input.registry,
        checkpoint: RegistryCheckpoint {
            previous: next,
            publishers: stored.publishers.clone(),
        },
        prior_checkpoint_digest: hash(stored.canonical_bytes().as_bytes()),
    })
}

#[cfg(test)]
pub(in crate::package_registry::trust) mod tests;
