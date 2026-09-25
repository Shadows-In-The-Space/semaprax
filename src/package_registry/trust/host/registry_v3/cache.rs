use super::*;
use crate::package_registry::registry_v3::RegistrySnapshotV3;
use crate::package_registry::trust::array;

pub struct CacheFill<'registry, 'input> {
    pub expected_generation_digest: &'input str,
    pub lock: &'input str,
    pub registry: &'registry RegistrySnapshotV3,
    pub trusted_time: u64,
}
/// Plain copied-subject receipt, not a persistent registry-trust capability.
pub struct CacheFillReceipt {
    pub generation_digest: String,
    pub lock_digest: String,
    pub subjects: Vec<CachedSubject>,
}
pub struct CachedSubject {
    pub package: String,
    pub version: String,
    pub subject_digest: String,
    pub present: bool,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
pub(super) fn populate(
    path: &Path,
    generation: &generation::Generation,
    request: &CacheFill<'_, '_>,
    mut recheck: impl FnMut() -> Result<()>,
    mut read: impl FnMut(&ArtifactRead<'_, '_>) -> Result<VerifiedArtifact>,
) -> std::result::Result<CacheFillReceipt, Vec<crate::diagnostic::Diagnostic>> {
    let subjects = array(
        &generation.value["cache"]["subjects"],
        crate::package_registry::MAX_ENTRIES,
    )
    .and_then(|rows| {
        rows.iter()
            .map(|row| Ok(string(row)?.to_owned()))
            .collect::<Result<Vec<_>>>()
    })
    .map_err(|error| vec![error])?;
    let mut verified = false;
    let states = crate::package_cache_host::publish_bound(path, request.lock, &subjects, || {
        recheck().map_err(|error| vec![error])?;
        #[cfg(test)]
        point();
        if !verified {
            // Ordinary cache authority is acquired before signature replay. No
            // metadata flag or decoded snapshot substitutes for these live reads.
            let mut count = 0;
            for entry in request.registry.entries() {
                let publication = entry.publication();
                if subjects.contains(&publication.subject_bytes) {
                    read(&ArtifactRead {
                        expected_generation_digest: request.expected_generation_digest,
                        lock: request.lock,
                        registry: request.registry,
                        package: &publication.package,
                        version: &publication.version,
                        path: "module.wasm",
                        trusted_time: request.trusted_time,
                    })
                    .map_err(|error| vec![error])?;
                    count += 1;
                }
            }
            if count == 0 || count != subjects.len() {
                return Err(vec![refused("cache bridge selected inventory disagrees")]);
            }
            verified = true;
        }
        recheck().map_err(|error| vec![error])
    })?;
    let mut rows = Vec::new();
    for bytes in &subjects {
        let subject = crate::package_lock_v3::verify_dependency_subject(bytes)
            .map_err(|error| vec![error])?;
        let name = format!(
            "{}.json",
            subject
                .subject_digest
                .strip_prefix("sha256:")
                .expect("verified digest")
        );
        rows.push(CachedSubject {
            package: subject.coordinate.package,
            version: subject.coordinate.version,
            subject_digest: subject.subject_digest,
            present: states[&name],
        });
    }
    rows.sort_by(|a, b| (&a.package, &a.version).cmp(&(&b.package, &b.version)));
    Ok(CacheFillReceipt {
        generation_digest: request.expected_generation_digest.into(),
        lock_digest: hash(request.lock.as_bytes()),
        subjects: rows,
    })
}

#[cfg(test)]
thread_local! {pub(super) static HOOK:std::cell::RefCell<Option<Box<dyn FnMut()>>>=const {std::cell::RefCell::new(None)};}
#[cfg(test)]
fn point() {
    HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook();
        }
    });
}
