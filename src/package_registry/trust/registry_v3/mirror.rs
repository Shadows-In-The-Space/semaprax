//! Exact acquired-metadata composition. Downloaded bytes remain untrusted
//! until the ordinary Registry-v3 verifier authenticates them against the
//! independently installed root and durable checkpoint.

use super::*;
use crate::package_registry::mirror_transport::{MirrorBytes, MirrorObjectKind};
use std::collections::BTreeSet;

/// One exact publisher role and its caller-selected immutable metadata path.
pub struct MirrorPublisherPath<'a> {
    pub role: &'a str,
    pub path: &'a str,
}

/// Names the complete metadata set expected from one already-authorized mirror
/// acquisition. The sealed registry is supplied independently; remote bytes
/// cannot create or decode their way into this type.
pub struct MirrorMetadataPaths<'registry, 'path> {
    pub timestamp_path: &'path str,
    pub snapshot_path: &'path str,
    pub publishers: &'path [MirrorPublisherPath<'path>],
    pub registry: &'registry registry::RegistrySnapshotV3,
}

/// Replays acquired mirror metadata through the ordinary signature, snapshot,
/// publisher-manifest, revocation and checkpoint verifier. It never fetches,
/// writes, installs roots, or returns a durable/fetch capability.
pub fn verify_mirror_update<'registry>(
    root: &InstalledRoot,
    stored: &RegistryCheckpoint,
    now: u64,
    paths: &MirrorMetadataPaths<'registry, '_>,
    downloaded: &[MirrorBytes],
) -> Result<RegistryUpdateCandidate<'registry>> {
    // A first independently authorized installation has no timestamp stamp.
    // Afterwards, reject a mirror that has been offline beyond the explicit
    // Wavect freshness interval even if its old signed expiry was longer.
    if stored.previous.roles.contains_key("timestamp")
        && now
            .checked_sub(stored.previous.observed_time)
            .filter(|elapsed| *elapsed <= MAX_MIRROR_OFFLINE_SECONDS)
            .is_none()
    {
        return Err(stale());
    }

    let mut expected_paths = BTreeSet::new();
    for path in std::iter::once(paths.timestamp_path)
        .chain(std::iter::once(paths.snapshot_path))
        .chain(paths.publishers.iter().map(|publisher| publisher.path))
    {
        if !expected_paths.insert(path) {
            return Err(binding());
        }
    }
    let mut roles = BTreeSet::new();
    if paths
        .publishers
        .iter()
        .any(|publisher| !roles.insert(publisher.role))
        || downloaded.len() != expected_paths.len()
    {
        return Err(binding());
    }
    for item in downloaded {
        if item.kind != MirrorObjectKind::Metadata || !expected_paths.contains(item.path.as_str()) {
            return Err(binding());
        }
    }
    let metadata = |path| {
        let matches = downloaded
            .iter()
            .filter(|item| item.path == path)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(binding());
        }
        std::str::from_utf8(matches[0].bytes()).map_err(|_| shape())
    };
    let timestamp = metadata(paths.timestamp_path)?;
    let snapshot = metadata(paths.snapshot_path)?;
    let publishers = paths
        .publishers
        .iter()
        .map(|publisher| Ok((publisher.role, metadata(publisher.path)?)))
        .collect::<Result<Vec<_>>>()?;
    verify_update(
        root,
        stored,
        now,
        &UpdateInputs {
            timestamp,
            snapshot,
            publishers: &publishers,
            registry: paths.registry,
        },
    )
}
