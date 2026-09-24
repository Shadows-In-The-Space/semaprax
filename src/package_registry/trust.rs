//! TUF-style local policy v1, not a TUF wire implementation. Verification is
//! pure and yields a NON-authoritative candidate: no durable checkpoint store,
//! clock, network, cache publication, or fetch permission is provided here.
use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};

use super::registry_v2::{ManifestBoundEntry, RegistrySnapshotV2};
use crate::diagnostic::Diagnostic;

const ROOT_SCHEMA: &str = "semaprax.registry-trust-root.v1";
const METADATA_SCHEMA: &str = "semaprax.registry-trust-metadata.v1";
const CHECKPOINT_SCHEMA: &str = "semaprax.registry-trust-checkpoint.v1";
const SIGN_DOMAIN: &[u8] = b"semaprax.registry-trust-metadata.v1\0";
const MAX_BYTES: usize = 1024 * 1024;
const MAX_ROLES: usize = 19;
const MAX_KEYS: usize = 64;
type Result<T> = std::result::Result<T, Diagnostic>;

fn error(code: &'static str, message: &str) -> Diagnostic {
    Diagnostic::io(code, message)
}
fn shape() -> Diagnostic {
    error(
        "SPX-PKR621",
        "registry trust wire or policy is outside the closed profile",
    )
}
fn signature() -> Diagnostic {
    error(
        "SPX-PKR622",
        "registry trust signature threshold or delegated authority refused",
    )
}
fn stale() -> Diagnostic {
    error(
        "SPX-PKR623",
        "registry trust metadata expired, rolled back, equivocated, or changed root",
    )
}
fn binding() -> Diagnostic {
    error(
        "SPX-PKR624",
        "registry trust exact metadata, manifest, or artifact binding disagrees",
    )
}
fn hash(bytes: &[u8]) -> String {
    crate::audit_capsule::sha256_digest(bytes)
}
fn wire(value: &Value) -> String {
    serde_json::to_string(value).expect("JSON value serializes")
}

fn parse(bytes: &str) -> Result<Value> {
    crate::package_build::wire::validate_compact_json_keys(
        bytes,
        MAX_BYTES,
        "registry trust metadata",
    )
    .map_err(|_| shape())?;
    let value: Value = serde_json::from_str(bytes).map_err(|_| shape())?;
    if wire(&value) != bytes {
        return Err(shape());
    }
    Ok(value)
}
fn fields(value: &Value, names: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or_else(shape)?;
    if object.len() != names.len() || names.iter().any(|name| !object.contains_key(*name)) {
        return Err(shape());
    }
    Ok(())
}
fn text(value: &Value) -> Result<&str> {
    value.as_str().filter(|s| s.len() <= 512).ok_or_else(shape)
}
fn number(value: &Value) -> Result<u64> {
    value.as_u64().ok_or_else(shape)
}
fn positive(value: &Value) -> Result<u64> {
    number(value).and_then(|n| if n == 0 { Err(shape()) } else { Ok(n) })
}
fn array(value: &Value, limit: usize) -> Result<&[Value]> {
    value
        .as_array()
        .filter(|v| v.len() <= limit)
        .map(Vec::as_slice)
        .ok_or_else(shape)
}
fn hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(shape());
    }
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| shape())?;
    }
    Ok(result)
}
fn digest(value: &Value) -> Result<String> {
    let value = text(value)?;
    hex::<32>(value.strip_prefix("sha256:").ok_or_else(shape)?)?;
    Ok(value.to_owned())
}
fn label(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(shape());
    }
    Ok(())
}

struct Role {
    namespace: String,
    keys: BTreeSet<String>,
    threshold: usize,
}

/// Explicit out-of-band anchor. Parsing does not authenticate its origin. The
/// embedding host must install these bytes independently of distribution data.
pub struct InstalledRoot {
    registry: String,
    version: u64,
    expires: u64,
    digest: String,
    keys: BTreeMap<String, VerifyingKey>,
    roles: BTreeMap<String, Role>,
}
impl InstalledRoot {
    pub fn from_independently_installed_bytes(bytes: &str) -> Result<Self> {
        let value = parse(bytes)?;
        fields(
            &value,
            &["schema", "registry", "version", "expires", "keys", "roles"],
        )?;
        if value["schema"] != ROOT_SCHEMA {
            return Err(shape());
        }
        let registry = text(&value["registry"])?.to_owned();
        label(&registry)?;
        let mut keys = BTreeMap::new();
        for row in array(&value["keys"], MAX_KEYS)? {
            fields(row, &["keyid", "public"])?;
            let public = hex::<32>(text(&row["public"])?)?;
            let keyid = digest(&row["keyid"])?;
            let key = VerifyingKey::from_bytes(&public).map_err(|_| shape())?;
            if key.is_weak() || keyid != hash(&public) || keys.insert(keyid, key).is_some() {
                return Err(shape());
            }
        }
        let mut roles = BTreeMap::new();
        let mut used_keys = BTreeSet::new();
        let mut namespaces = Vec::<String>::new();
        for row in array(&value["roles"], MAX_ROLES)? {
            fields(row, &["name", "namespace", "keyids", "threshold"])?;
            let name = text(&row["name"])?.to_owned();
            label(&name)?;
            let namespace = text(&row["namespace"])?.to_owned();
            if name == "root" || name == "timestamp" || name == "snapshot" {
                if !namespace.is_empty() {
                    return Err(shape());
                }
            } else {
                let base = namespace.strip_suffix('.').ok_or_else(shape)?;
                super::validate_identity(base).map_err(|_| shape())?;
                if base == "std"
                    || base.starts_with("std.")
                    || namespaces
                        .iter()
                        .any(|p| namespace.starts_with(p) || p.starts_with(&namespace))
                {
                    return Err(shape());
                }
                namespaces.push(namespace.clone());
            }
            let mut role_keys = BTreeSet::new();
            for key in array(&row["keyids"], MAX_KEYS)? {
                let id = digest(key)?;
                if !keys.contains_key(&id) || !role_keys.insert(id.clone()) || !used_keys.insert(id)
                {
                    return Err(shape());
                }
            }
            let threshold = usize::try_from(positive(&row["threshold"])?).map_err(|_| shape())?;
            if threshold > role_keys.len()
                || roles
                    .insert(
                        name,
                        Role {
                            namespace,
                            keys: role_keys,
                            threshold,
                        },
                    )
                    .is_some()
            {
                return Err(shape());
            }
        }
        if !roles.contains_key("root")
            || !roles.contains_key("timestamp")
            || !roles.contains_key("snapshot")
            || namespaces.is_empty()
            || used_keys.len() != keys.len()
        {
            return Err(shape());
        }
        Ok(Self {
            registry,
            version: positive(&value["version"])?,
            expires: positive(&value["expires"])?,
            digest: hash(bytes.as_bytes()),
            keys,
            roles,
        })
    }
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Cryptographically verified one-version root transition, still not committed
/// to a durable trust store. Never replace a store from unauthenticated download.
pub struct RootRotationCandidate {
    root: InstalledRoot,
    previous_root_digest: String,
}
impl RootRotationCandidate {
    #[must_use]
    pub fn root(&self) -> &InstalledRoot {
        &self.root
    }
    #[must_use]
    pub fn previous_root_digest(&self) -> &str {
        &self.previous_root_digest
    }
}

/// Root rotation requires distinct-key thresholds from BOTH current and new
/// root roles. Expired old roots may authenticate recovery; the new root must
/// be fresh and exactly one version newer. No timestamp key can rotate roots.
pub fn verify_root_rotation(
    current: &InstalledRoot,
    envelope: &str,
    now: u64,
) -> Result<RootRotationCandidate> {
    let value = parse(envelope)?;
    fields(&value, &["signed", "signatures"])?;
    let root_bytes = wire(&value["signed"]);
    let next = InstalledRoot::from_independently_installed_bytes(&root_bytes)?;
    if next.registry != current.registry
        || current.version.checked_add(1) != Some(next.version)
        || next.expires <= now
    {
        return Err(stale());
    }
    let old_role = &current.roles["root"];
    let new_role = &next.roles["root"];
    let mut old_signers = BTreeSet::new();
    let mut new_signers = BTreeSet::new();
    let mut all_signers = BTreeSet::new();
    let mut message = b"semaprax.registry-trust-root.v1\0".to_vec();
    message.extend_from_slice(root_bytes.as_bytes());
    // A rotation may need the union of two disjoint full root key sets.
    for row in array(&value["signatures"], MAX_KEYS * 2)? {
        fields(row, &["keyid", "sig"])?;
        let id = digest(&row["keyid"])?;
        if !all_signers.insert(id.clone()) {
            return Err(signature());
        }
        let sig = Signature::from_bytes(&hex::<64>(text(&row["sig"])?)?);
        let old = old_role.keys.contains(&id);
        let new = new_role.keys.contains(&id);
        if !old && !new {
            return Err(signature());
        }
        if old {
            current.keys[&id]
                .verify_strict(&message, &sig)
                .map_err(|_| signature())?;
            old_signers.insert(id.clone());
        }
        if new {
            next.keys[&id]
                .verify_strict(&message, &sig)
                .map_err(|_| signature())?;
            new_signers.insert(id);
        }
    }
    if old_signers.len() < old_role.threshold || new_signers.len() < new_role.threshold {
        return Err(signature());
    }
    Ok(RootRotationCandidate {
        root: next,
        previous_root_digest: current.digest.clone(),
    })
}

#[derive(Clone)]
struct Stamp {
    version: u64,
    digest: String,
}

/// Checkpoint *data*, not proof of durable storage. The caller must retain the
/// latest successful candidate through its trusted store before subsequent use.
#[derive(Clone)]
pub struct Checkpoint {
    registry: String,
    root_version: u64,
    root_digest: String,
    observed_time: u64,
    roles: BTreeMap<String, Stamp>,
}
impl Checkpoint {
    /// Only for explicit first installation, never a missing/corrupt-store fallback.
    #[must_use]
    pub fn initial(root: &InstalledRoot) -> Self {
        Self {
            registry: root.registry.clone(),
            root_version: root.version,
            root_digest: root.digest.clone(),
            observed_time: 0,
            roles: BTreeMap::new(),
        }
    }
    /// The host, not this parser, authenticates checkpoint storage and freshness.
    pub fn from_trusted_store_bytes(bytes: &str) -> Result<Self> {
        let value = parse(bytes)?;
        fields(
            &value,
            &[
                "schema",
                "registry",
                "root_version",
                "root_digest",
                "observed_time",
                "roles",
            ],
        )?;
        if value["schema"] != CHECKPOINT_SCHEMA {
            return Err(shape());
        }
        let registry = text(&value["registry"])?.to_owned();
        label(&registry)?;
        let mut roles = BTreeMap::new();
        for row in array(&value["roles"], MAX_ROLES)? {
            fields(row, &["role", "version", "digest"])?;
            let name = text(&row["role"])?.to_owned();
            label(&name)?;
            if roles
                .insert(
                    name,
                    Stamp {
                        version: positive(&row["version"])?,
                        digest: digest(&row["digest"])?,
                    },
                )
                .is_some()
            {
                return Err(shape());
            }
        }
        let checkpoint = Self {
            registry,
            root_version: positive(&value["root_version"])?,
            root_digest: digest(&value["root_digest"])?,
            observed_time: number(&value["observed_time"])?,
            roles,
        };
        // A future store CAS binds the bytes actually read, not a repaired
        // ordering of equivalent role stamps.
        if checkpoint.canonical_bytes() != bytes {
            return Err(shape());
        }
        Ok(checkpoint)
    }
    #[must_use]
    pub fn canonical_bytes(&self) -> String {
        let roles = self
            .roles
            .iter()
            .map(|(name, stamp)| json!({"role":name,"version":stamp.version,"digest":stamp.digest}))
            .collect::<Vec<_>>();
        wire(
            &json!({"schema":CHECKPOINT_SCHEMA,"registry":self.registry,"root_version":self.root_version,"root_digest":self.root_digest,"observed_time":self.observed_time,"roles":roles}),
        )
    }
}

struct Metadata {
    payload: Value,
    version: u64,
    digest: String,
}
fn authenticate(
    root: &InstalledRoot,
    checkpoint: &Checkpoint,
    role: &str,
    bytes: &str,
    now: u64,
) -> Result<Metadata> {
    let value = parse(bytes)?;
    fields(&value, &["signed", "signatures"])?;
    let signed = &value["signed"];
    fields(
        signed,
        &[
            "schema",
            "registry",
            "root_digest",
            "role",
            "version",
            "expires",
            "payload",
        ],
    )?;
    if signed["schema"] != METADATA_SCHEMA
        || signed["registry"] != root.registry
        || signed["root_digest"] != root.digest
        || signed["role"] != role
    {
        return Err(signature());
    }
    let authority = root.roles.get(role).ok_or_else(signature)?;
    let mut message = SIGN_DOMAIN.to_vec();
    message.extend_from_slice(wire(signed).as_bytes());
    let mut signed_keys = BTreeSet::new();
    for row in array(&value["signatures"], MAX_KEYS)? {
        fields(row, &["keyid", "sig"])?;
        let keyid = digest(&row["keyid"])?;
        if !authority.keys.contains(&keyid) || !signed_keys.insert(keyid.clone()) {
            return Err(signature());
        }
        let sig = Signature::from_bytes(&hex::<64>(text(&row["sig"])?)?);
        root.keys[&keyid]
            .verify_strict(&message, &sig)
            .map_err(|_| signature())?;
    }
    if signed_keys.len() < authority.threshold {
        return Err(signature());
    }
    let version = positive(&signed["version"])?;
    let hash = hash(bytes.as_bytes());
    if positive(&signed["expires"])? <= now
        || checkpoint.roles.get(role).is_some_and(|old| {
            version < old.version || (version == old.version && hash != old.digest)
        })
    {
        return Err(stale());
    }
    Ok(Metadata {
        payload: signed["payload"].clone(),
        version,
        digest: hash,
    })
}

fn matches_blob(reference: &Value, bytes: &[u8], maximum: usize) -> Result<()> {
    fields(reference, &["length", "sha256"])?;
    if bytes.len() > maximum
        || positive(&reference["length"])? != bytes.len() as u64
        || digest(&reference["sha256"])? != hash(bytes)
    {
        return Err(binding());
    }
    Ok(())
}
fn matches_metadata(reference: &Value, bytes: &str, metadata: &Metadata) -> Result<()> {
    fields(reference, &["version", "file"])?;
    if positive(&reference["version"])? != metadata.version {
        return Err(binding());
    }
    matches_blob(&reference["file"], bytes.as_bytes(), MAX_BYTES)
}

/// Complete caller-owned inputs. Names are logical role identifiers, never paths.
pub struct UpdateInputs<'a> {
    pub timestamp: &'a str,
    pub snapshot: &'a str,
    pub publishers: &'a [(&'a str, &'a str)],
    pub registry_snapshot: &'a str,
    pub admitted_entries: &'a [ManifestBoundEntry],
}

/// Verified local evidence plus a required checkpoint transition. This type is
/// intentionally NOT a publication/fetch capability and has no promotion API.
pub struct RegistryUpdateCandidate {
    registry: RegistrySnapshotV2,
    checkpoint: Checkpoint,
    prior_checkpoint_digest: String,
}
impl RegistryUpdateCandidate {
    #[must_use]
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }
    #[must_use]
    pub fn prior_checkpoint_digest(&self) -> &str {
        &self.prior_checkpoint_digest
    }
    #[must_use]
    pub fn registry_snapshot_digest(&self) -> &str {
        self.registry.digest()
    }

    /// Pure evidence check: yanked entries always refuse in this initial policy.
    /// Caller still has no permission to fetch, publish, execute, or advance state.
    pub fn check_lock(&self, lock: &str, subjects: &[String]) -> Result<()> {
        for subject in subjects {
            if !self.registry.entries().iter().any(|entry| {
                entry.publication().subject_bytes == *subject
                    && entry.publication().status == super::PublicationStatus::Active
            }) {
                return Err(error(
                    "SPX-PKR625",
                    "subject is absent or yanked in this authenticated candidate",
                ));
            }
        }
        crate::package_lock_v3::verify(
            lock,
            subjects,
            &crate::package_lock_v3::LockOptions::default(),
        )?;
        Ok(())
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
        if entry.publication().status != super::PublicationStatus::Active {
            return Err(error("SPX-PKR625", "yanked artifact is refused"));
        }
        let manifest = super::artifact_manifest::verify(
            entry.artifact_manifest_bytes(),
            entry.artifact_manifest_digest(),
        )?;
        let row = manifest
            .input()
            .artifacts
            .iter()
            .find(|row| row.path == path)
            .ok_or_else(binding)?;
        if row.bytes != bytes.len() || row.sha256 != hash(bytes) {
            return Err(binding());
        }
        Ok(())
    }
}

/// Verifies against explicit anchor, prior trusted checkpoint data, and one
/// fixed caller-supplied Unix time. Nothing is durably committed by this call.
pub fn verify_update(
    root: &InstalledRoot,
    checkpoint: &Checkpoint,
    now: u64,
    input: &UpdateInputs<'_>,
) -> Result<RegistryUpdateCandidate> {
    if root.registry != checkpoint.registry
        || root.expires <= now
        || now < checkpoint.observed_time
        || root.version < checkpoint.root_version
        || (root.version == checkpoint.root_version && root.digest != checkpoint.root_digest)
    {
        return Err(stale());
    }
    if input.publishers.len() != root.roles.len() - 3 {
        return Err(binding());
    }
    let timestamp = authenticate(root, checkpoint, "timestamp", input.timestamp, now)?;
    fields(&timestamp.payload, &["snapshot"])?;
    let snapshot = authenticate(root, checkpoint, "snapshot", input.snapshot, now)?;
    matches_metadata(&timestamp.payload["snapshot"], input.snapshot, &snapshot)?;
    fields(&snapshot.payload, &["registry", "publishers"])?;
    matches_blob(
        &snapshot.payload["registry"],
        input.registry_snapshot.as_bytes(),
        super::registry_v2::MAX_SNAPSHOT_BYTES,
    )?;
    let refs = array(&snapshot.payload["publishers"], MAX_ROLES)?;
    if refs.len() != input.publishers.len() {
        return Err(binding());
    }
    let mut names = BTreeSet::new();
    let mut target_rows = BTreeMap::new();
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
        let metadata = authenticate(root, checkpoint, name, bytes, now)?;
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
        for row in array(&metadata.payload["targets"], super::MAX_ENTRIES)? {
            fields(row, &["package", "version", "manifest"])?;
            let package = text(&row["package"])?;
            let version = text(&row["version"])?;
            if !package.starts_with(&role.namespace) {
                return Err(signature());
            }
            if target_rows
                .insert(
                    (package.to_owned(), version.to_owned()),
                    row["manifest"].clone(),
                )
                .is_some()
                || target_rows.len() > super::MAX_ENTRIES
            {
                return Err(binding());
            }
        }
        next.roles.insert(
            (*name).to_owned(),
            Stamp {
                version: metadata.version,
                digest: metadata.digest,
            },
        );
    }
    // Crucial: decoder output alone cannot establish independently replayed
    // source/build/API provenance. Require the existing sealed admission type.
    let registry =
        super::registry_v2::verify_snapshot(input.registry_snapshot, input.admitted_entries)?;
    if target_rows.len() != registry.entries().len() {
        return Err(binding());
    }
    for entry in registry.entries() {
        let publication = entry.publication();
        let reference = target_rows
            .get(&(publication.package.clone(), publication.version.clone()))
            .ok_or_else(binding)?;
        matches_blob(
            reference,
            entry.artifact_manifest_bytes().as_bytes(),
            super::artifact_manifest::MAX_MANIFEST_BYTES,
        )?;
    }
    next.root_version = root.version;
    next.root_digest = root.digest.clone();
    next.observed_time = now;
    next.roles.insert(
        "timestamp".to_owned(),
        Stamp {
            version: timestamp.version,
            digest: timestamp.digest,
        },
    );
    next.roles.insert(
        "snapshot".to_owned(),
        Stamp {
            version: snapshot.version,
            digest: snapshot.digest,
        },
    );
    if next.roles.len() > MAX_ROLES {
        return Err(shape());
    }
    Ok(RegistryUpdateCandidate {
        registry,
        checkpoint: next,
        prior_checkpoint_digest: hash(checkpoint.canonical_bytes().as_bytes()),
    })
}

#[cfg(test)]
mod tests;
