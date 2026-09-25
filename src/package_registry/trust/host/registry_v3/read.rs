use super::*;
use crate::package_registry::registry_v3::RegistrySnapshotV3;
use crate::package_registry::trust::{array, fields, MAX_ROLES};

/// Explicit caller authority is scoped to one held generation, exact semantic
/// lock and logical manifest path. No field is an ambient filesystem path.
pub struct ArtifactRead<'registry, 'input> {
    pub expected_generation_digest: &'input str,
    pub lock: &'input str,
    pub registry: &'registry RegistrySnapshotV3,
    pub package: &'input str,
    pub version: &'input str,
    pub path: &'input str,
    pub trusted_time: u64,
}

/// Immutable bytes returned by a completed live read. The bindings are evidence,
/// not a serializable token authorizing later store reads or artifact execution.
pub struct VerifiedArtifact {
    bytes: Vec<u8>,
    generation_digest: String,
    lock_digest: String,
    artifact_digest: String,
    package: String,
    version: String,
    path: String,
    verified_at: u64,
}
impl VerifiedArtifact {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    pub fn generation_digest(&self) -> &str {
        &self.generation_digest
    }
    pub fn lock_digest(&self) -> &str {
        &self.lock_digest
    }
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }
    pub fn package(&self) -> &str {
        &self.package
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
}

pub(super) fn verify(
    generation: &generation::Generation,
    request: &ArtifactRead<'_, '_>,
) -> Result<VerifiedArtifact> {
    let generation_digest = hash(generation.bytes.as_bytes());
    if request.expected_generation_digest != generation_digest {
        return Err(refused("artifact read generation CAS disagrees"));
    }
    let value = &generation.value;
    fields(&value["cache"], &["lock", "subjects", "artifacts"])?;
    if string(&value["cache"]["lock"])? != request.lock {
        return Err(refused("artifact read lock CAS disagrees"));
    }
    let metadata = &value["metadata"];
    fields(
        metadata,
        &["timestamp", "snapshot", "publishers", "registry"],
    )?;
    if string(&metadata["registry"])? != request.registry.envelope() {
        return Err(refused("artifact read requires exact sealed registry"));
    }
    let publishers = array(&metadata["publishers"], MAX_ROLES)?
        .iter()
        .map(|row| {
            fields(row, &["role", "bytes"])?;
            Ok((string(&row["role"])?, string(&row["bytes"])?))
        })
        .collect::<Result<Vec<_>>>()?;
    // Replay exact held signed bytes at the supplied trusted time, not the
    // commit's old time. Inspect/decode APIs cannot provide the required seal.
    let candidate = proof::verify_update(
        &generation.root,
        &generation.checkpoint,
        request.trusted_time,
        &proof::UpdateInputs {
            timestamp: string(&metadata["timestamp"])?,
            snapshot: string(&metadata["snapshot"])?,
            publishers: &publishers,
            registry: request.registry,
        },
    )?;
    let subjects = array(
        &value["cache"]["subjects"],
        crate::package_registry::MAX_ENTRIES,
    )?
    .iter()
    .map(|value| Ok(string(value)?.to_owned()))
    .collect::<Result<Vec<_>>>()?;
    candidate.check_lock(request.lock, &subjects)?;
    let entry = request
        .registry
        .entries()
        .iter()
        .find(|entry| {
            entry.publication().package == request.package
                && entry.publication().version == request.version
        })
        .ok_or_else(|| refused("artifact read coordinate missing"))?;
    if !subjects.contains(&entry.publication().subject_bytes) {
        return Err(refused("artifact read outside locked subjects"));
    }
    let mut selected = None;
    for row in array(
        &value["cache"]["artifacts"],
        crate::package_registry::MAX_ENTRIES * 3,
    )? {
        fields(row, &["package", "version", "path", "hex"])?;
        if row["package"] == request.package
            && row["version"] == request.version
            && row["path"] == request.path
        {
            if selected.replace(row).is_some() {
                return Err(refused("duplicate cached artifact"));
            }
        }
    }
    let row = selected.ok_or_else(|| refused("artifact was not selected in held generation"))?;
    let encoded = string(&row["hex"])?;
    if encoded.len() > super::super::MAX_GENERATION / 2
        || encoded.len() % 2 != 0
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refused("invalid cached artifact encoding"));
    }
    let bytes = (0..encoded.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&encoded[index..index + 2], 16)
                .map_err(|_| refused("invalid cached artifact hex"))
        })
        .collect::<Result<Vec<_>>>()?;
    candidate.check_artifact(request.package, request.version, request.path, &bytes)?;
    Ok(VerifiedArtifact {
        artifact_digest: hash(&bytes),
        bytes,
        generation_digest,
        lock_digest: hash(request.lock.as_bytes()),
        package: request.package.into(),
        version: request.version.into(),
        path: request.path.into(),
        verified_at: request.trusted_time,
    })
}

#[cfg(test)]
thread_local! {pub(super) static BEFORE_RELEASE:std::cell::RefCell<Option<Box<dyn FnOnce()>>>=const {std::cell::RefCell::new(None)};}
#[cfg(test)]
pub(super) fn before_release() {
    BEFORE_RELEASE.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}
